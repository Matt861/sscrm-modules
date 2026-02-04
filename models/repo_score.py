from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryScores:
    stars_score: int
    forks_score: int
    prevalence_score: int
    maturity_score: int
    last_updated_score: int
    trusted_org_bonus: int
    unclass_score: int
    passes_sia: str