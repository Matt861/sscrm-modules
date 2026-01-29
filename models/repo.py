from __future__ import annotations

from dataclasses import dataclass, field
from multiprocessing import RLock
from typing import Dict, List, Optional, Union, Iterable
from pathlib import Path

@dataclass
class PackageInfo:
    name: str
    version: str
    group: str
    repo_url: str

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
    statecode: str = ""
    statedistrict: str = ""
    county: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    location: Optional[LatLon] = None


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


@dataclass
class RepositoryInfo:
    repo_url: str

    # Keep these if you still want them in memory; CSV writer will ignore them
    owner: str
    name: str

    stars: int
    forks: int
    releases_count: int
    tags_count: int
    closed_issues_count: int
    created_at: str
    updated_at: str

    retrieval_uuid: str = ""
    retrieved_at: str = ""

    contributors: List[ContributorInfo] = field(default_factory=list)
    repo_scores: Optional[RepositoryScores] = None


@dataclass(frozen=True)
class RepositoryScores:
    stars_score: int
    forks_score: int
    #releases_score: int
    #tags_score: int
    #closed_issues_score: int
    prevalence_score: int
    maturity_score: int
    last_updated_score: int
    trusted_org_bonus: int
    unclass_score: int
    passes_sia: str


class RepositoryStore:
    def __init__(self) -> None:
        self._by_uuid: Dict[str, RepositoryInfo] = {}
        self._by_url: Dict[str, str] = {}

    @staticmethod
    def _normalize_url(url: str) -> str:
        return url.strip().rstrip("/")

    def add(self, repo: RepositoryInfo) -> None:
        norm = self._normalize_url(repo.repo_url)
        self._by_uuid[repo.retrieval_uuid] = repo
        self._by_url[norm] = repo.retrieval_uuid

    def get_all(self) -> List[RepositoryInfo]:
        return list(self._by_uuid.values())

    def get_by_uuid(self, retrieval_uuid: str) -> Optional[RepositoryInfo]:
        return self._by_uuid.get(retrieval_uuid)

    def get_by_url(self, repo_url: str) -> Optional[RepositoryInfo]:
        rid = self._by_url.get(self._normalize_url(repo_url))
        return self._by_uuid.get(rid) if rid else None

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
