from typing import Optional
import constants
from configuration import Configuration as Config
from datetime import datetime, timezone
from models.repo import RepositoryScores
from repo_metrics.prevalence import stars_score, forks_score, maturity_score, last_updated_score, closed_issues_score, \
    trusted_org_bonus, releases_score


def tags_or_releases_prevalence_calculator(repo_data):
    if repo_data.releases_count > 0:
        return round(constants.PREVALENCE_WEIGHT * releases_score(repo_data.releases_count))
    elif repo_data.tags_count > 0:
        return round(constants.PREVALENCE_WEIGHT * releases_score(repo_data.tags_count))

    return 0

def get_prevalence_score(closed_issues_score, tags_or_releases_prevalence_score):
    if tags_or_releases_prevalence_score > closed_issues_score:
        return tags_or_releases_prevalence_score
    elif closed_issues_score > tags_or_releases_prevalence_score:
        return closed_issues_score
    return tags_or_releases_prevalence_score

def is_score_passing(unclass_score):
    if unclass_score:
        if unclass_score >= 70:
            return "True"
        elif unclass_score >= 40:
            return "Undetermined"
        else:
            return "False"
    else:
        return "False"

def years_since_date_calculator(repo_date: str, *, now: Optional[datetime] = None,) -> float:
    """
    Calculate years since created_at and years since last_updated.

    Inputs:
      - created_at / last_updated: ISO-8601 strings (e.g. "2024-01-01T12:34:56Z"
        or "2024-01-01T12:34:56+00:00"). If naive (no timezone), treated as UTC.

    Returns:
      (years_since_created, years_since_last_updated)

    Notes:
      - Uses a mean tropical year (365.2425 days) for better long-range accuracy.
      - Returns 0.0 for any value that can't be parsed.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    def _parse_iso(s: str) -> Optional[datetime]:
        s = (s or "").strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    def _years_between(then: Optional[datetime]) -> float:
        if then is None:
            return 0.0
        seconds = (now - then).total_seconds()
        if seconds < 0:
            return 0.0
        return seconds / (365.2425 * 86400.0)

    repo_dt = _parse_iso(repo_date)

    return _years_between(repo_dt)


def calculate_repo_scores():
    for repo_data in Config.github_repository_store.get_all():
        stars_score_final = round(constants.STARS_WEIGHT * stars_score(repo_data.stars))
        forks_score_final = round(constants.FORKS_WEIGHT * forks_score(repo_data.forks))
        created_date_years = years_since_date_calculator(repo_data.created_at)
        maturity_score_final = round(constants.MATURITY_WEIGHT * maturity_score(created_date_years))
        last_updated_date_years = years_since_date_calculator(repo_data.updated_at)
        last_updated_score_final = round(constants.LAST_UPDATED_WEIGHT * last_updated_score(last_updated_date_years))
        closed_issues_score_final = round(constants.PREVALENCE_WEIGHT * closed_issues_score(repo_data.closed_issues_count))
        tags_or_releases_prevalence_score = tags_or_releases_prevalence_calculator(repo_data)
        prevalence_score = get_prevalence_score(closed_issues_score_final, tags_or_releases_prevalence_score)
        trusted_org_score = trusted_org_bonus(repo_data.repo_url)
        unclass_score = stars_score_final + forks_score_final + maturity_score_final + last_updated_score_final + \
                        prevalence_score + trusted_org_score
        passes_sia = is_score_passing(unclass_score)

        repo_scores = RepositoryScores(
            stars_score=stars_score_final,
            forks_score=forks_score_final,
            maturity_score=maturity_score_final,
            last_updated_score=last_updated_score_final,
            prevalence_score=prevalence_score,
            trusted_org_bonus=trusted_org_score,
            unclass_score=unclass_score,
            passes_sia=passes_sia
        )

        repo_data.repo_scores = repo_scores
