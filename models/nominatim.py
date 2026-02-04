from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ----------------------------
# Models for the compiled address
# ----------------------------

@dataclass(frozen=True)
class LatLon:
    lat: float
    lon: float


@dataclass(frozen=True)
class InternalAddress:
    query: str
    formatted_address: str
    street: str = ""
    house_number: str = ""
    suburb: str = ""
    postcode: str = ""
    state: str = ""
    state_code: str = ""
    state_district: str = ""
    county: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    location: Optional[LatLon] = None