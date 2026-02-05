from typing import Optional, Dict, Any

from configuration import Configuration as Config
import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry


class DependencyTrackClient:
    def __init__(self,) -> None:
        """
        base_url should be the root URL of your dependency-track instance,
        e.g. "https://dependency-track.example.com"
        api_key is the API key configured in Dependency-Track (X-Api-Key).
        """
        self.base_url = Config.dtrack_base_url.rstrip("/")
        self.api_key = Config.dtrack_api_key
        self.verify = Config.dtrack_verify_tls
        self.timeout = Config.dtrack_timeout
        self.proxies = Config.proxies

        self.session = requests.Session()
        retries = Retry(
            total=Config.dtrack_max_retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.session.headers.update(
            {
                "X-Api-Key": self.api_key,
                "Accept": "application/json",
                "User-Agent": "dependency-track-python-client/1.0",
            }
        )


    def url(self, path: str) -> str:
        # All API endpoints are under /api/v1
        path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}/api/v1{path}"


    def request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = self.url(path)
        resp = self.session.request(method, url, params=params, timeout=self.timeout, proxies=self.proxies, verify=self.verify)
        resp.raise_for_status()
        if resp.content:
            return resp.json()
        return None