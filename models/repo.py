from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from models.contributor import ContributorInfo
from models.repo_score import RepositoryScores


@dataclass
class RepositoryInfo:
    repo_url: str
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