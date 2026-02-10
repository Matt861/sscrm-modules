import json
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone
from models.contributor import ContributorInfo
from models.nominatim import InternalAddress
from models.repo import RepositoryInfo


def _iso_z_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RepoMetricsCache:
    """
    Per-repo JSON cache with TTL.

    Cache file format:
      {
        "cached_at": "2026-02-10T12:34:56Z",
        "repo_key": "owner/name",
        "data": { ... RepositoryInfo as dict ... }
      }
    """

    def __init__(self, cache_dir: Path, *, ttl_days: int = 10) -> None:
        self.cache_dir = cache_dir
        self.ttl = timedelta(days=ttl_days)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @staticmethod
    def _safe_key(owner: str, name: str) -> str:
        # stable filename for each repo
        owner = (owner or "").strip()
        name = (name or "").strip()
        key = f"{owner}__{name}".replace("/", "_")
        return key

    def _path_for(self, owner: str, name: str) -> Path:
        return self.cache_dir / f"{self._safe_key(owner, name)}.json"

    @staticmethod
    def _now_utc() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _iso_z(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_iso(s: str) -> Optional[datetime]:
        s = (s or "").strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    def _is_fresh(self, cached_at: Optional[str], path: Path) -> bool:
        """
        Freshness check uses cached_at if present; otherwise falls back to file mtime.
        """
        now = self._now_utc()

        dt = self._parse_iso(cached_at or "")
        if dt is not None:
            return (now - dt) <= self.ttl

        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            return (now - mtime) <= self.ttl
        except Exception:
            return False

    def read(self, owner: str, name: str) -> Optional[RepositoryInfo]:
        """
        Return RepositoryInfo if cache exists and is fresh, else None.
        """
        path = self._path_for(owner, name)
        if not path.exists():
            return None

        with self._lock:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    return None

                cached_at = payload.get("cached_at")
                if not self._is_fresh(cached_at, path):
                    return None

                data = payload.get("data")
                if not isinstance(data, dict):
                    return None

                return repo_from_dict(data)
            except Exception:
                # corrupted cache: ignore
                return None

    def write(self, repo: RepositoryInfo) -> Path:
        """
        Write/overwrite the cache JSON (this resets the 10-day timer).
        """
        path = self._path_for(repo.owner, repo.name)
        with self._lock:
            payload = {
                "cached_at": self._iso_z(self._now_utc()),
                "repo_key": f"{repo.owner}/{repo.name}",
                "data": repo_to_dict(repo),
            }
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path


    def update_contributors(
        self,
        owner: str,
        name: str,
        contributors: List[Any],
    ) -> Optional[Path]:
        """
        Update ONLY contributors inside an existing repo metrics cache file.

        - Preserves existing "cached_at" (metrics TTL anchor).
        - Adds/updates "contributors_cached_at" timestamp.
        - Writes contributors into payload["data"]["contributors"].

        Returns the updated cache file Path, or None if cache file doesn't exist / is unreadable.
        """
        path = self._path_for(owner, name)
        if not path.exists():
            # Requirement says "existing repository metrics JSON cache files"
            return None

        with self._lock:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    return None

                data = payload.get("data")
                if not isinstance(data, dict):
                    return None

                # Convert dataclasses -> dict
                contrib_dicts: List[dict] = []
                for c in contributors:
                    if is_dataclass(c):
                        contrib_dicts.append(asdict(c))
                    elif isinstance(c, dict):
                        contrib_dicts.append(c)
                    else:
                        # best-effort: ignore unknown types
                        continue

                data["contributors"] = contrib_dicts
                payload["data"] = data

                # Separate timestamp for contributor freshness tracking (optional)
                payload["contributors_cached_at"] = _iso_z_now()

                # IMPORTANT: do NOT touch payload["cached_at"] here
                path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                return path
            except Exception:
                return None


# ============================================================
# Dataclass <-> dict helpers (for cache round-trip)
# ============================================================

def repo_to_dict(repo: RepositoryInfo) -> Dict[str, Any]:
    # asdict handles nested dataclasses; InternalAddress becomes dict automatically
    return asdict(repo)


def repo_from_dict(d: Dict[str, Any]) -> RepositoryInfo:
    raw_contribs = d.get("contributors") or []
    contributors: List[ContributorInfo] = []

    if isinstance(raw_contribs, list):
        for c in raw_contribs:
            if not isinstance(c, dict):
                continue

            # internal_address (optional)
            ia_obj: Optional[InternalAddress] = None
            ia = c.get("internal_address")
            if isinstance(ia, dict):
                try:
                    ia_obj = InternalAddress(**ia)
                except TypeError:
                    # tolerate schema drift
                    ia_obj = None

            # tolerate key drift: github_id vs githubid
            github_id_val = c.get("github_id")
            if github_id_val is None:
                github_id_val = c.get("githubid", 0)

            contributors.append(
                ContributorInfo(
                    login=str(c.get("login") or ""),
                    github_id=int(github_id_val or 0),
                    contributions=int(c.get("contributions") or 0),
                    html_url=str(c.get("html_url") or ""),
                    name=c.get("name"),
                    company=c.get("company"),
                    email=c.get("email"),
                    location=c.get("location"),
                    internal_address=ia_obj,  # <-- key part
                )
            )

    return RepositoryInfo(
        owner=str(d.get("owner") or ""),
        name=str(d.get("name") or ""),
        repo_url=str(d.get("repo_url") or ""),
        stars=int(d.get("stars") or 0),
        forks=int(d.get("forks") or 0),
        releases_count=int(d.get("releases_count") or 0),
        tags_count=int(d.get("tags_count") or 0),
        closed_issues_count=int(d.get("closed_issues_count") or 0),
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
        contributors=contributors,  # <-- now filled from cache
        retrieval_uuid=str(d.get("retrieval_uuid") or ""),
        retrieved_at=str(d.get("retrieved_at") or ""),
    )


# def repo_from_dict(d: Dict[str, Any]) -> RepositoryInfo:
#     # contributors need to be rebuilt into ContributorSummary / InternalAddress
#     contributors_in: List[ContributorInfo] = []
#     raw_contribs = d.get("contributors") or []
#     if isinstance(raw_contribs, list):
#         for c in raw_contribs:
#             if not isinstance(c, dict):
#                 continue
#             ia = c.get("internal_address")
#             ia_obj: Optional[InternalAddress] = None
#             if isinstance(ia, dict):
#                 ia_obj = InternalAddress(**ia)
#             contributors_in.append(
#                 ContributorInfo(
#                     login=str(c.get("login") or ""),
#                     github_id=int(c.get("github_id") or 0),
#                     contributions=int(c.get("contributions") or 0),
#                     html_url=str(c.get("html_url") or ""),
#                     name=c.get("name"),
#                     company=c.get("company"),
#                     email=c.get("email"),
#                     location=c.get("location"),
#                     internal_address=ia_obj,
#                 )
#             )
#
#     return RepositoryInfo(
#         owner=str(d.get("owner") or ""),
#         name=str(d.get("name") or ""),
#         repo_url=str(d.get("repo_url") or ""),
#         stars=int(d.get("stars") or 0),
#         forks=int(d.get("forks") or 0),
#         releases_count=int(d.get("releases_count") or 0),
#         tags_count=int(d.get("tags_count") or 0),
#         closed_issues_count=int(d.get("closed_issues_count") or 0),
#         created_at=d.get("created_at"),
#         updated_at=d.get("updated_at"),
#         contributors=contributors_in,
#         retrieval_uuid=str(d.get("retrieval_uuid") or ""),
#         retrieved_at=str(d.get("retrieved_at") or ""),
#     )