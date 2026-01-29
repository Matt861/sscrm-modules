import json
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any
import requests

from models.repo import InternalAddress
from repo_metrics.rate_limiter import RateLimiter


# ----------------------------
# Nominatim client
# ----------------------------
class NominatimClient:
    """
    Nominatim search client with:
      - 1 req/sec throttling
      - retry/backoff for transient failures
      - optional disk cache
    """

    def __init__(
        self,
        *,
        base_url: str = "https://nominatim.openstreetmap.org",
        user_agent: str = "github-metrics",
        email: Optional[str] = None,
        min_interval_seconds: float = 1.05,
        cache_path: Optional[Path] = None,
        timeout_seconds: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = int(timeout_seconds)

        self.session = requests.Session()
        self.session.headers.update(
            {
                # Nominatim policy: provide a valid identifying UA.
                "User-Agent": user_agent,
                "Accept": "application/json",
            }
        )

        self.email = email
        self.limiter = RateLimiter(min_interval_seconds=min_interval_seconds)

        # Cache: key is normalized query string
        self._cache_lock = threading.Lock()
        self._cache: Dict[str, Optional[Dict[str, Any]]] = {}

        self.cache_path = cache_path
        if self.cache_path:
            self._load_cache_file()

    def _load_cache_file(self) -> None:
        try:
            if self.cache_path and self.cache_path.exists():
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    # stored values are dict or None
                    self._cache.update(data)
        except Exception:
            # If cache is corrupted, ignore rather than failing the run
            pass

    def _save_cache_file(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    @staticmethod
    def _norm_query(q: str) -> str:
        return " ".join(q.strip().split()).lower()

    def geocode_to_internal_address(self, query: str) -> Optional[InternalAddress]:
        """
        Returns InternalAddress (best match) or None if no result / error.
        """
        raw = self._search_best(query)
        if not raw:
            return None
        from repo_metrics.geolocator import _compile_internal_address
        return _compile_internal_address(query, raw)

    def _search_best(self, query: str) -> Optional[Dict[str, Any]]:
        q_norm = self._norm_query(query)
        if not q_norm:
            return None

        # Cache hit
        with self._cache_lock:
            if q_norm in self._cache:
                return self._cache[q_norm]  # may be None

        params = {
            "q": query,
            "format": "jsonv2",
            "addressdetails": 1,
            "limit": 1,
        }
        if self.email:
            params["email"] = self.email

        url = f"{self.base_url}/search"

        # Retry policy (lightweight)
        backoff = 2.0
        for attempt in range(1, 6):
            self.limiter.wait()
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except requests.exceptions.RequestException:
                # transient network issue
                time.sleep(backoff)
                backoff = min(backoff * 2.0, 30.0)
                continue

            # Hard block / forbidden: stop early to avoid hammering
            if resp.status_code == 403:
                # You may be blocked (common if policy violated). Cache as None to avoid repeats.
                with self._cache_lock:
                    self._cache[q_norm] = None
                self._save_cache_file()
                return None

            # Too many requests / service busy
            if resp.status_code in (429, 503, 504):
                time.sleep(backoff)
                backoff = min(backoff * 2.0, 30.0)
                continue

            if resp.status_code >= 400:
                # cache negative result and move on
                with self._cache_lock:
                    self._cache[q_norm] = None
                self._save_cache_file()
                return None

            try:
                payload = resp.json()
            except ValueError:
                time.sleep(backoff)
                backoff = min(backoff * 2.0, 30.0)
                continue

            best: Optional[Dict[str, Any]] = None
            if isinstance(payload, list) and payload:
                item = payload[0]
                if isinstance(item, dict):
                    best = item

            with self._cache_lock:
                self._cache[q_norm] = best
            self._save_cache_file()
            return best

        # All retries failed
        with self._cache_lock:
            self._cache[q_norm] = None
        self._save_cache_file()
        return None