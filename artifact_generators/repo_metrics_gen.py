from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, List, Union

from models.repo import RepositoryInfo, RepositoryStore


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
    overwrite: bool = True,
    encoding: str = "utf-8",
) -> Path:
    """
    Write RepositoryInfo items to a CSV file.

    Args:
        repos: Iterable of RepositoryInfo
        csv_path: output CSV path
        overwrite: overwrite existing file if True, else raise FileExistsError
    """
    out_path = Path(csv_path).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists() and not overwrite:
        raise FileExistsError(f"CSV already exists: {out_path}")

    with out_path.open("w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for repo in repos:
            writer.writerow(_repo_to_row(repo))

    return out_path


def write_repo_store_to_csv(
    store: RepositoryStore,
    csv_path: Union[str, Path],
    *,
    overwrite: bool = True,
    encoding: str = "utf-8",
) -> Path:
    """
    Convenience wrapper for RepositoryStore.
    """
    return write_repo_infos_to_csv(
        repos=store.get_all(),
        csv_path=csv_path,
        overwrite=overwrite,
        encoding=encoding,
    )
