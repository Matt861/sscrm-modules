from __future__ import annotations
from configuration import Configuration as Config
import json
import math
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List
from utils import dir_to_tar_gz_flat


def _iso_z(dt_str: str) -> str:
    s = (dt_str or "").strip()
    if not s:
        return ""
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return s


def _safe_filename(name: str) -> str:
    s = (name or "").strip()
    s = re.sub(r"[^\w.\-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "repo"


def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _coerce_float(v: Any, default: float = 0.0) -> float:
    try:
        f = float(v)
        if math.isfinite(f):
            return f
        return default
    except Exception:
        return default


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default)


def _internal_address_to_json_dict(internal_address: Any, *, fallback_query: str) -> dict:
    """
    internal_address can be:
      - None
      - InternalAddress dataclass
      - dict already in the desired shape
    """
    if internal_address is None:
        return {}

    if isinstance(internal_address, dict):
        d = dict(internal_address)
        d.setdefault("query", fallback_query)
        return d

    if is_dataclass(internal_address):
        d = asdict(internal_address)

        # ensure "query" exists / matches
        if not d.get("query"):
            d["query"] = fallback_query

        # normalize nested LatLon -> {"lat": ..., "lon": ...}
        loc = d.get("location")
        if loc is None:
            d["location"] = {"lat": None, "lon": None}
        elif isinstance(loc, dict):
            d["location"] = {"lat": loc.get("lat"), "lon": loc.get("lon")}
        else:
            # unexpected; keep safe
            d["location"] = {"lat": None, "lon": None}

        return d

    # unknown type
    return {}


def main() -> None:
    """
    Creates 1 JSON file per repository object, named after the repository (e.g. json-smart-v2.json).

    Expects each repo object to have (best-effort):
      - owner, name, repo_url
      - retrieval_uuid, retrieved_at
      - stars, forks, releases_count, closed_issues_count
      - created_at, updated_at
      - contributors: list of ContributorSummary-like objects with:
          login, github_id, contributions, name, company, location, internal_address
    """
    github_metrics_output_dir = Path(Config.project_output_dir, Config.github_metrics_output_folder_name)
    github_metrics_output_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    for repo in Config.github_repository_store.get_all():
        owner = str(_get_attr(repo, "owner", "") or _get_attr(repo, "org", "") or "")
        name = str(_get_attr(repo, "name", "") or "")
        url = str(_get_attr(repo, "repo_url", "") or _get_attr(repo, "url", "") or "")

        scan_id = str(_get_attr(repo, "retrieval_uuid", "") or _get_attr(repo, "scanid", "") or "")
        scan_date = str(_get_attr(repo, "retrieved_at", "") or _get_attr(repo, "scandate", "") or "")

        if not scan_date:
            scan_date = now_utc

        created_at = str(_get_attr(repo, "created_at", "") or "")
        updated_at = str(_get_attr(repo, "updated_at", "") or "")

        age_days = 0.0
        last_update_hours = 0.0
        try:
            if created_at:
                cdt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                if cdt.tzinfo is None:
                    cdt = cdt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - cdt.astimezone(timezone.utc)).total_seconds() / 86400.0
        except Exception:
            age_days = 0.0
        try:
            if updated_at:
                udt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                if udt.tzinfo is None:
                    udt = udt.replace(tzinfo=timezone.utc)
                last_update_hours = (datetime.now(timezone.utc) - udt.astimezone(timezone.utc)).total_seconds() / 3600.0
        except Exception:
            last_update_hours = 0.0

        repo_scores = _get_attr(repo, "repo_scores", []) or []
        prevalence_score = _coerce_int(_get_attr(repo_scores, "prevalence_score", 0), 0)
        stars_score = _coerce_int(_get_attr(repo_scores, "stars_score", 0), 0)
        forks_score = _coerce_int(_get_attr(repo_scores, "forks_score", 0), 0)
        maturity_score = _coerce_int(_get_attr(repo_scores, "maturity_score", 0), 0)
        last_update_score = _coerce_int(_get_attr(repo_scores, "last_updated_score", 0), 0)
        trusted_org_bonus = _coerce_int(_get_attr(repo_scores, "trusted_org_bonus", 0), 0)
        total_score = _coerce_int(_get_attr(repo_scores, "unclass_score", 0), 0)

        contributors_out: List[dict] = []
        total_contributors = 0

        contributors = _get_attr(repo, "contributors", []) or []
        for c in contributors:
            github_id = _coerce_int(_get_attr(c, "github_id", 0), 0)
            contribution = _coerce_int(_get_attr(c, "contributions", 0), 0)
            total_contributors += contribution

            contributor_name = str(_get_attr(c, "name", "") or "")
            organization = str(_get_attr(c, "company", "") or "")
            location = str(_get_attr(c, "location", "") or "")

            internal_address = _internal_address_to_json_dict(
                _get_attr(c, "internal_address", None),
                fallback_query=location,
            )

            contributors_out.append(
                {
                    "scan_id": scan_id,
                    "scan_date": _iso_z(scan_date),
                    "github_id": github_id,
                    "name": contributor_name,
                    "organization": organization,
                    "location": location,
                    "internal_address": internal_address,
                    "contribution": contribution,
                }
            )

        payload = {
            "org": owner,
            "name": name,
            "url": url,
            "scan_id": scan_id,
            "scan_date": _iso_z(scan_date),
            "stars": _coerce_int(_get_attr(repo, "stars", 0), 0),
            "forks": _coerce_int(_get_attr(repo, "forks", 0), 0),
            "closed_issues": _coerce_int(_get_attr(repo, "closed_issues_count", 0), 0),
            "releases": _coerce_int(_get_attr(repo, "releases_count", 0), 0),
            "age_days": _coerce_float(age_days, 0.0),
            "last_update_hours": _coerce_float(last_update_hours, 0.0),
            "prevalence_score": prevalence_score,
            "stars_score": stars_score,
            "forks_score": forks_score,
            "maturity_score": maturity_score,
            "last_update_score": last_update_score,
            "trusted_org_bonus": trusted_org_bonus,
            "total_score": total_score,
            "contributors": contributors_out,
            "contribution_total": total_contributors,
        }

        out_path = github_metrics_output_dir / f"{_safe_filename(name)}.json"
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(out_path)

    dir_to_tar_gz_flat(github_metrics_output_dir)
    print(f"Successfully generated: {len(written)} github metric jsons.")


if __name__ == "__main__":
    main()
