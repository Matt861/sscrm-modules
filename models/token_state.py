from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class TokenState:
    session: requests.Session
    cooldown_until: float = 0.0
    gql_remaining: Optional[int] = None
    gql_reset_unix: float = 0.0

    # NEW: last observed values
    gql_last_cost: Optional[int] = None
    gql_last_remaining: Optional[int] = None
    gql_last_reset_at: Optional[str] = None
    gql_requests: int = 0
    # session: requests.Session
    # cooldown_until: float = 0.0
    #
    # # GraphQL token-awareness
    # gql_remaining: Optional[int] = None
    # gql_reset_unix: float = 0.0  # seconds since epoch (UTC)