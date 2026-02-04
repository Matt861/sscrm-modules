from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, List, Union
from configuration import Configuration as Config
from models.repo import RepositoryInfo


CSV_FIELDS: List[str] = [
    "repo_url",
    "stars",
    "forks",
    "releases_count",
    "tags_count",
    "closed_issues_count",
    "created_at",
    "updated_at",
    "retrieval_uuid",
    "retrieved_at",
]


def _repo_to_row(repo: RepositoryInfo) -> dict:
    """
    Convert RepositoryInfo -> CSV row dict, excluding owner/name/contributors.
    We explicitly whitelist fields to ensure we never write disallowed data.
    """
    return {field: getattr(repo, field) for field in CSV_FIELDS}


def write_repo_infos_to_csv(
    repos: Iterable[RepositoryInfo],
    csv_path: Union[str, Path],
    *,
    encoding: str = "utf-8",
) -> None:
    """
    Write RepositoryInfo items to a CSV file.

    Args:
        repos: Iterable of RepositoryInfo
        csv_path: output CSV path
        overwrite: overwrite existing file if True, else raise FileExistsError
    """
    out_path = Path(csv_path).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for repo in repos:
            writer.writerow(_repo_to_row(repo))

    print(f"Successfully generated file: {out_path}")


def main(*, encoding: str = "utf-8",) -> None:
    """
    Convenience wrapper for RepositoryStore.
    """
    github_metrics_csv_file_path = Path(Config.project_output_dir, Config.github_metrics_file_name)

    write_repo_infos_to_csv(
        repos=Config.github_repository_store.get_all(),
        csv_path=github_metrics_csv_file_path,
        encoding=encoding,
    )


if __name__ == "__main__":
    main()
