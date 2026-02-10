# import uuid
# from pathlib import Path
# from typing import Iterable, List, Tuple
# from datetime import datetime, timedelta, timezone
#
# from models.contributor import ContributorInfo
# from models.repo import RepositoryInfo
# from repo_metrics.github.github_perf_client import GitHubPerfClient
# from repo_metrics.github.repo_metrics_cache import RepoMetricsCache
#
#
# # ============================================================
# # URL parsing (assumes you already have a robust one elsewhere)
# # ============================================================
#
# def parse_github_repo_url(repo_url: str) -> Tuple[str, str]:
#     """
#     Parse https://github.com/<owner>/<repo> into (owner, repo).
#     Minimal on purpose (reuse your existing version if you have one).
#     """
#     u = (repo_url or "").strip()
#     if u.startswith("http://"):
#         u = "https://" + u[len("http://") :]
#     if not u.startswith("https://github.com/"):
#         raise ValueError(f"Not a GitHub URL: {repo_url}")
#     parts = [p for p in u.split("/") if p]
#     if len(parts) < 4:
#         raise ValueError(f"Invalid GitHub URL: {repo_url}")
#     owner = parts[2]
#     repo = parts[3].removesuffix(".git")
#     return owner, repo
#
#
# # ============================================================
# # Metrics collection (replace bodies with your real logic)
# # ============================================================
#
# def collect_repo_info(gh: GitHubPerfClient, owner: str, repo: str, repo_url: str) -> RepositoryInfo:
#     """
#     Fetch metrics for one repo (stubbed to common REST calls).
#     Replace this with your existing implementation (stars/forks/releases/tags/closed issues/contributors/etc).
#     """
#     # repo metadata
#     r = gh.rest_get_json(f"/repos/{owner}/{repo}")
#     stars = int(r.get("stargazers_count") or 0)
#     forks = int(r.get("forks_count") or 0)
#     created_at = r.get("created_at")
#     updated_at = r.get("updated_at")
#
#     # releases count (paginate if you want exact; this is a simple approximation)
#     releases = gh.rest_get_json(f"/repos/{owner}/{repo}/releases", params={"per_page": 1, "page": 1})
#     releases_count = 0
#     if isinstance(releases, list):
#         # If you already have a better exact counter, keep it
#         releases_count = len(releases)
#
#     # tags count (simple: first page length; replace with your exact paginator)
#     tags = gh.rest_get_json(f"/repos/{owner}/{repo}/tags", params={"per_page": 1, "page": 1})
#     tags_count = 0
#     if isinstance(tags, list):
#         tags_count = len(tags)
#
#     # closed issues count: you likely use GraphQL or /search/issues in your real code
#     closed_issues_count = 0
#
#     # contributors list: replace with your real contributor enrichment + internal_address attachment
#     contributors: List[ContributorInfo] = []
#
#     return RepositoryInfo(
#         owner=owner,
#         name=repo,
#         repo_url=repo_url,
#         stars=stars,
#         forks=forks,
#         releases_count=releases_count,
#         tags_count=tags_count,
#         closed_issues_count=closed_issues_count,
#         created_at=created_at,
#         updated_at=updated_at,
#         contributors=contributors,
#         retrieval_uuid=str(uuid.uuid4()),
#         retrieved_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
#     )
#
#
# def collect_one_repo(
#     gh: GitHubPerfClient,
#     cache: RepoMetricsCache,
#     repo_url: str,
# ) -> RepositoryInfo:
#     """
#     NEW: cache-aware collection:
#       - if fresh cache exists => return it
#       - else fetch => write cache => return
#     """
#     owner, repo = parse_github_repo_url(repo_url)
#
#     cached = cache.read(owner, repo)
#     if cached is not None:
#         return cached
#
#     fresh = collect_repo_info(gh, owner, repo, repo_url)
#
#     # write/overwrite cache (resets the 10-day window)
#     cache.write(fresh)
#     return fresh
#
#
# # ============================================================
# # Example entry point (optional)
# # ============================================================
#
# def collect_from_urls(
#     repo_urls: Iterable[str],
#     *,
#     tokens: List[str],
#     cache_dir: Path,
# ) -> List[RepositoryInfo]:
#     gh = GitHubPerfClient(tokens=tokens)
#     cache = RepoMetricsCache(cache_dir=cache_dir, ttl_days=10)
#
#     results: List[RepositoryInfo] = []
#     for url in repo_urls:
#         results.append(collect_one_repo(gh, cache, url))
#     return results