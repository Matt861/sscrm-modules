from __future__ import annotations

from dataclasses import dataclass
from multiprocessing import RLock
from typing import Dict, List, Optional, Union, Iterable

from models.nominatim import InternalAddress


@dataclass
class ContributorInfo:
    login: str
    github_id: int
    contributions: int
    html_url: str

    # New fields from /users/{login}
    name: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    site_admin: bool = False
    location: Optional[str] = None

    internal_address: Optional[InternalAddress] = None


class ContributorStore:
    """
    In-memory store for ContributorSummary objects with fast lookup by:
      - login (case-insensitive)
      - github_id

    Supports upsert semantics: adding the same login/github_id again replaces the stored object.
    Thread-safe for concurrent reads/writes.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_login: Dict[str, ContributorInfo] = {}
        self._by_id: Dict[int, ContributorInfo] = {}

    @staticmethod
    def _norm_login(login: str) -> str:
        return login.strip().lower()

    def add(self, contributor: ContributorInfo) -> None:
        """
        Add or replace a contributor in the store.
        Keeps both indexes (login + id) consistent.
        """
        if not contributor.login:
            raise ValueError("ContributorSummary.login must be non-empty")

        login_key = self._norm_login(contributor.login)
        github_id = int(contributor.github_id)

        with self._lock:
            # If an entry already exists for this login, remove its old github_id mapping if it changed
            existing = self._by_login.get(login_key)
            if existing is not None and int(existing.github_id) != github_id:
                self._by_id.pop(int(existing.github_id), None)

            # If an entry already exists for this github_id, remove its old login mapping if it changed
            existing_by_id = self._by_id.get(github_id)
            if existing_by_id is not None and self._norm_login(existing_by_id.login) != login_key:
                self._by_login.pop(self._norm_login(existing_by_id.login), None)

            self._by_login[login_key] = contributor
            self._by_id[github_id] = contributor

    def add_many(self, contributors: Iterable[ContributorInfo]) -> None:
        for c in contributors:
            self.add(c)

    def get_by_login(self, login: str) -> Optional[ContributorInfo]:
        if not login:
            return None
        with self._lock:
            return self._by_login.get(self._norm_login(login))

    def get_by_githubid(self, github_id: Union[int, str]) -> Optional[ContributorInfo]:
        try:
            gid = int(github_id)
        except Exception:
            return None
        with self._lock:
            return self._by_id.get(gid)

    def remove_by_login(self, login: str) -> bool:
        if not login:
            return False
        key = self._norm_login(login)
        with self._lock:
            existing = self._by_login.pop(key, None)
            if existing is None:
                return False
            self._by_id.pop(int(existing.github_id), None)
            return True

    def remove_by_githubid(self, github_id: Union[int, str]) -> bool:
        try:
            gid = int(github_id)
        except Exception:
            return False
        with self._lock:
            existing = self._by_id.pop(gid, None)
            if existing is None:
                return False
            self._by_login.pop(self._norm_login(existing.login), None)
            return True

    def all(self) -> List[ContributorInfo]:
        with self._lock:
            # Return unique objects (login index is canonical)
            return list(self._by_login.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_login)