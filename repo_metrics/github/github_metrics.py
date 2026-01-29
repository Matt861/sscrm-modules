from __future__ import annotations
from configuration import Configuration as Config
import sys
import utils
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterable, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from models import component
from models.component import Component
from models.repo import RepositoryInfo, RepositoryStore
from repo_metrics.github.github_perf_client import GitHubPerfClient
from repo_metrics.graphql_queries import REPO_METRICS_GQL
from loggers.github_metrics_logger import github_metrics_logger as logger


# ----------------------------
# URL parsing
# ----------------------------
def parse_github_repo_url(url: str) -> Tuple[str, str, str]:
    """
    Accepts:
      https://github.com/owner/repo
      http://github.com/owner/repo
      https://github.com/owner/repo.git
      git@github.com:owner/repo.git

    Normalizes to https://github.com/owner/repo
    """
    u = url.strip()

    ssh_m = re.match(r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$", u)
    if ssh_m:
        owner, repo = ssh_m.group(1), ssh_m.group(2)
        return f"https://github.com/{owner}/{repo}", owner, repo

    # Normalize http -> https for github.com
    u = re.sub(r"^http://github\.com/", "https://github.com/", u, flags=re.IGNORECASE)

    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", u, flags=re.IGNORECASE)
    if not m:
        raise ValueError(logger.error(f"Not a recognized GitHub repo URL: {url}"))

    owner = m.group(1)
    repo = m.group(2)
    return f"https://github.com/{owner}/{repo}", owner, repo


# ----------------------------
# Collection
# ----------------------------
def collect_one_repo(repo_url: str,) -> RepositoryInfo:
    norm_url, owner, name = parse_github_repo_url(repo_url)

    # GraphQL for counts + dates (1 call)
    data = Config.github_perf_client.graphql(REPO_METRICS_GQL, {"owner": owner, "name": name})
    repo = data.get("repository") or {}
    if not repo:
        raise RuntimeError(logger.error(f"GraphQL returned no repository data for {owner}/{name}"))

    # Contributors (REST; 1..N calls depending on max_contributors)
    #contributors = gh.list_contributors(owner, name)

    retrieval_uuid = str(uuid.uuid4())
    retrieved_at = datetime.now(timezone.utc).isoformat()

    return RepositoryInfo(
        repo_url=norm_url,
        owner=owner,
        name=name,
        stars=int(repo.get("stargazerCount", 0)),
        forks=int(repo.get("forkCount", 0)),
        releases_count=int((repo.get("releases") or {}).get("totalCount", 0)),
        tags_count=int((repo.get("refs") or {}).get("totalCount", 0)),
        closed_issues_count=int((repo.get("issues") or {}).get("totalCount", 0)),
        created_at=str(repo.get("createdAt", "")),
        updated_at=str(repo.get("updatedAt", "")),
        #contributors=contributors,
        retrieval_uuid=retrieval_uuid,
        retrieved_at=retrieved_at,
    )


def collect_many_repos(repo_urls: Iterable[str], *, max_workers: int = 24,) -> List[RepositoryInfo]:
    """
    High-throughput collector for 100s of repos.

    Tips:
      - Start with max_workers ~ 16-32. Too high can trigger secondary rate limits.
      - If contributors are large, set max_contributors lower, or you’ll pay in REST calls.
    """

    urls = [u.strip() for u in repo_urls if u and u.strip() and not u.strip().startswith("#")]
    results: List[RepositoryInfo] = []
    errors: List[str] = []
    Config.github_repository_store = RepositoryStore()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {
            ex.submit(collect_one_repo, url): url
            for url in urls
        }
        for fut in as_completed(fut_map):
            url = fut_map[fut]
            try:
                results.append(fut.result())
                Config.github_repository_store.add(fut.result())
                component.set_repo_info_for_repo_url(
                    components=Config.component_store.get_all_components(),
                    repo_url=url,
                    repo_info=fut.result(),
                    normalize_fn=utils.normalize_github_url,
                )
            except Exception as e:
                errors.append(f"{url}: {e}")

    # If you prefer "fail-fast", raise if errors
    if errors:
        # Keep partial results and still surface failures
        msg = "Some repos failed:\n" + "\n".join(errors[:25])
        if len(errors) > 25:
            msg += f"\n... and {len(errors) - 25} more"
        # You can change this to a print if you don't want exceptions.
        raise RuntimeError(logger.error(msg))

    return results


def main():
    # url_file = Path(Config.root_dir, "input/urls/github/github_urls_maven.json")
    # #urls = ["https://github.com/netplex/json-smart-v2"]
    # urls: List[str] = []
    # if url_file:
    #     json_data = utils.read_json_file(url_file)
    #     for prop, value in utils.iter_properties(json_data):
    #         urls.append(value)
    #
    # if not urls:
    #     sys.exit((logger.error("No Github repository URLs provided.", file=sys.stderr)))

    components = Config.component_store.get_all_components()

    # Collect repo_urls, skipping None/blank, and dedupe while preserving order
    unique_repo_urls = list(dict.fromkeys(
        c.repo_url.strip()
        for c in components
        if c.repo_url and c.repo_url.strip()
    ))

    Config.github_perf_client = GitHubPerfClient()
    metrics = collect_many_repos(unique_repo_urls, max_workers=24,)
    for m in metrics:
        print(m.repo_url, m.releases_count, m.tags_count, m.stars, m.forks, m.closed_issues_count, len(m.contributors))


if __name__ == "__main__":
    raise SystemExit(main())