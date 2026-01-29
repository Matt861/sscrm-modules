from configuration import Configuration as Config
import os
import threading
import time
from datetime import datetime
from typing import Optional, List, Dict, Tuple
import requests
from models.token_state import TokenState


class TokenPool:
    """
    Thread-safe pool that:
      - rotates tokens for REST requests
      - is token-aware for GraphQL requests (prefers highest gql_remaining)
      - cools down tokens on rate limits
    """

    def __init__(self, user_agent: str = "perf-github-repo-metrics") -> None:
        raw: List[str] = []
        if Config.crt_sscrm_github_tokens:
            raw.extend([t.strip() for t in Config.crt_sscrm_github_tokens if t and t.strip()])

        env_tokens = os.getenv("GITHUB_TOKENS", "").strip()
        if env_tokens:
            raw.extend([t.strip() for t in env_tokens.split(",") if t.strip()])

        single = os.getenv("GITHUB_TOKEN", "").strip()
        if single:
            raw.append(single)

        # dedupe preserve order
        seen = set()
        self.tokens: List[str] = []
        for t in raw:
            if t not in seen:
                seen.add(t)
                self.tokens.append(t)

        # allow unauthenticated fallback (very low limits) if no tokens provided
        if not self.tokens:
            self.tokens = [""]

        self._lock = threading.Lock()
        self._rr_index = 0

        self._states: Dict[str, TokenState] = {}
        for tok in self.tokens:
            s = requests.Session()
            s.headers.update({
                "Accept": "application/vnd.github+json",
                "User-Agent": user_agent,
            })
            if tok:
                s.headers.update({"Authorization": f"Bearer {tok}"})
            self._states[tok] = TokenState(session=s)

    def _now(self) -> float:
        return time.time()

    def _parse_reset_header_unix(self, reset_header: Optional[str]) -> Optional[float]:
        if reset_header and reset_header.isdigit():
            return float(int(reset_header))
        return None

    def mark_rest_rate_limited(self, tok: str, resp: requests.Response) -> None:
        reset_unix = self._parse_reset_header_unix(resp.headers.get("X-RateLimit-Reset"))
        with self._lock:
            st = self._states[tok]
            if reset_unix:
                st.cooldown_until = max(st.cooldown_until, reset_unix + 1)
            else:
                st.cooldown_until = max(st.cooldown_until, self._now() + 30.0)

    def update_gql_budget(self, tok: str, rate_limit_obj: dict) -> None:
        """
        rate_limit_obj looks like:
          {"cost": 1, "remaining": 4999, "resetAt": "2026-01-27T20:31:12Z"}
        """
        remaining = rate_limit_obj.get("remaining")
        reset_at = rate_limit_obj.get("resetAt")

        reset_unix: Optional[float] = None
        if isinstance(reset_at, str) and reset_at:
            try:
                dt = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
                reset_unix = dt.timestamp()
            except Exception:
                reset_unix = None

        with self._lock:
            st = self._states[tok]

            # Existing: track remaining + reset unix for token-aware selection
            if isinstance(remaining, int):
                st.gql_remaining = remaining
            if reset_unix is not None:
                st.gql_reset_unix = reset_unix

            # NEW: track last observed rateLimit info for logging/debug
            cost = rate_limit_obj.get("cost")
            reset_at = rate_limit_obj.get("resetAt")

            if isinstance(cost, int):
                st.gql_last_cost = cost
            if isinstance(remaining, int):
                st.gql_last_remaining = remaining
            if isinstance(reset_at, str):
                st.gql_last_reset_at = reset_at

            st.gql_requests += 1

            # Existing: proactive cooldown if nearly drained (tune if needed)
            if isinstance(remaining, int) and remaining <= 50 and reset_unix and reset_unix > self._now():
                st.cooldown_until = max(st.cooldown_until, reset_unix + 1)

        # with self._lock:
        #     st = self._states[tok]
        #     if isinstance(remaining, int):
        #         st.gql_remaining = remaining
        #     if reset_unix is not None:
        #         st.gql_reset_unix = reset_unix
        #
        #     # proactive cooldown if nearly drained (tune if needed)
        #     if isinstance(remaining, int) and remaining <= 50 and reset_unix and reset_unix > self._now():
        #         st.cooldown_until = max(st.cooldown_until, reset_unix + 1)

    def pick_for_rest(self) -> Tuple[str, requests.Session]:
        """
        Round-robin among tokens not in cooldown.
        If all tokens are cooling down, pick the one that resets soonest.
        """
        with self._lock:
            now = self._now()
            n = len(self.tokens)

            # try N times to find an available token
            for _ in range(n):
                tok = self.tokens[self._rr_index % n]
                self._rr_index = (self._rr_index + 1) % n
                if self._states[tok].cooldown_until <= now:
                    return tok, self._states[tok].session

            # all are cooling down; pick the soonest
            tok = min(self.tokens, key=lambda t: self._states[t].cooldown_until)
            return tok, self._states[tok].session

    def pick_for_graphql(self) -> Tuple[str, requests.Session]:
        """
        Token-aware: prefer token with highest known gql_remaining that is not cooling down.
        Falls back to RR if no budgets known yet.
        """
        with self._lock:
            now = self._now()
            candidates = [t for t in self.tokens if self._states[t].cooldown_until <= now and self._states[t].gql_reset_unix <= now]

            if not candidates:
                tok = min(self.tokens, key=lambda t: self._states[t].cooldown_until)
                return tok, self._states[tok].session

            # if all unknown, RR among candidates
            if all(self._states[t].gql_remaining is None for t in candidates):
                # reuse RR index but only across candidates
                tok = candidates[self._rr_index % len(candidates)]
                self._rr_index = (self._rr_index + 1) % len(self.tokens)
                return tok, self._states[tok].session

            # pick max remaining (unknown treated as -1)
            tok = max(candidates, key=lambda t: (-1 if self._states[t].gql_remaining is None else self._states[t].gql_remaining))
            return tok, self._states[tok].session

    def print_gql_token_stats(self) -> None:
        with self._lock:
            now = time.time()
            for tok, st in self._states.items():
                tok_disp = (tok[:6] + "...") if tok else "<no-auth>"
                cd = st.cooldown_until - now
                cd_disp = f"{cd:.0f}s" if cd > 0 else "0s"
                print(
                    f"[GQL-STATS] token={tok_disp} "
                    f"reqs={st.gql_requests} "
                    f"last_cost={st.gql_last_cost} "
                    f"last_remaining={st.gql_last_remaining} "
                    f"resetAt={st.gql_last_reset_at} "
                    f"cooldown={cd_disp}"
                )
