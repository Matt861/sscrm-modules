from pathlib import Path

from configuration import Configuration as Config
from dataclasses import asdict
from typing import Dict, Any, Iterable, Optional

from models.nominatim import InternalAddress, LatLon
from repo_metrics.nominatim_client import NominatimClient


# ----------------------------
# Transform Nominatim -> requested structure
# ----------------------------

def _compile_internal_address(query: str, nominatim_item: Dict[str, Any]) -> InternalAddress:
    addr = nominatim_item.get("address") if isinstance(nominatim_item.get("address"), dict) else {}
    display = str(nominatim_item.get("display_name", "") or "")

    # Nominatim address keys vary by region. Use best-effort mapping.
    street = str(addr.get("road", "") or "")
    house_number = str(addr.get("house_number", "") or "")
    suburb = str(addr.get("suburb", "") or "")
    postcode = str(addr.get("postcode", "") or "")
    state = str(addr.get("state", "") or "")
    state_code = str(addr.get("state_code", "") or addr.get("state_code", "") or "")
    state_district = str(addr.get("state_district", "") or "")
    county = str(addr.get("county", "") or "")
    country = str(addr.get("country", "") or "")
    country_code = str(addr.get("country_code", "") or "").upper()

    # "city" can be city/town/village/hamlet depending on place type.
    city = (
        str(addr.get("city", "") or "")
        or str(addr.get("town", "") or "")
        or str(addr.get("village", "") or "")
        or str(addr.get("hamlet", "") or "")
        or str(addr.get("municipality", "") or "")
    )

    lat = nominatim_item.get("lat")
    lon = nominatim_item.get("lon")
    ll: Optional[LatLon] = None
    try:
        if lat is not None and lon is not None:
            ll = LatLon(lat=float(lat), lon=float(lon))
    except (TypeError, ValueError):
        ll = None

    return InternalAddress(
        query=query,
        formatted_address=display,
        street=street,
        house_number=house_number,
        suburb=suburb,
        postcode=postcode,
        state=state,
        state_code=state_code,
        state_district=state_district,
        county=county,
        country=country,
        country_code=country_code,
        city=city,
        location=ll,
    )


# ----------------------------
# Post-processing entry points
# ----------------------------

def geocode_all_contributor_locations(repo_objects: Iterable[Any],) -> Dict[str, Dict[str, Any]]:
    """
    After you've collected contributors for all repos, call this.

    Expects each repo object to have: repo.contributors (iterable of contributor objects)
    Expects each contributor object to have: contributor.login and contributor.location

    Returns mapping:
      { contributor_login: {"internal_address": <dict matching your schema>} }

    - Dedupes by contributor login (if the same contributor appears multiple times)
    - Dedupes by location string (cached inside NominatimClient too)
    """
    out: Dict[str, Dict[str, Any]] = {}

    # 1) Collect unique contributors with a non-empty location
    unique: Dict[str, str] = {}  # login -> location string
    for repo in repo_objects:
        contributors = getattr(repo, "contributors", []) or []
        for c in contributors:
            login = getattr(c, "login", None)
            loc = getattr(c, "location", None)
            if not login or not isinstance(login, str):
                continue
            if not loc or not isinstance(loc, str) or not loc.strip():
                continue
            # keep first observed location for that login
            unique.setdefault(login, loc.strip())

    # 2) Geocode each contributor's location (throttled + cached)
    for login, loc in unique.items():
        ia = Config.nominatim_client.geocode_to_internal_address(loc)
        if ia is None:
            continue
        out[login] = {"internal_address": _internal_address_to_dict(ia)}
        contributor = Config.contributor_store.get_by_login(login)
        contributor.internal_address = ia

    return out


def _internal_address_to_dict(ia: InternalAddress) -> Dict[str, Any]:
    d = asdict(ia)
    # Flatten LatLon to required structure if present
    if d.get("location") is None:
        d["location"] = {"lat": None, "lon": None}
    else:
        # already dict with keys lat/lon from asdict()
        pass

    return d


def main():
    print('geolocator')
    nominatim_cache_file_path = Path(Config.cache_dir, Config.nominatim_cache_file_name)
    Config.nominatim_client = NominatimClient(user_agent="github-metrics", cache_path=nominatim_cache_file_path,)
    contributor_addresses = geocode_all_contributor_locations(repo_objects=Config.github_repository_store.get_all(),)


if __name__ == "__main__":
    main()