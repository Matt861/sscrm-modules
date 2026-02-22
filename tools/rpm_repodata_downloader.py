#!/usr/bin/env python3
"""
Repodata bootstrap downloader (Windows-only, no CLI args)

What it does:
- For each repo in REPOS:
  - Downloads repodata/repomd.xml
  - Parses repomd.xml to find metadata objects (primary, filelists, other, updateinfo, etc.)
  - Downloads the referenced metadata files into the local repo directory
  - (Optional) Verifies checksums from repomd.xml

This gives you a local folder layout like:
  C:\sbom\repos\pgdg18-rhel9-x86_64\
    repodata\
      repomd.xml
      <hash>-primary.xml.gz
      <hash>-filelists.xml.gz
      ...

Then your SBOM generator can read those files without dnf/WSL/Linux.
"""

from configuration import Configuration as Config
import hashlib
import os
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# ----------------------------
# HARD-CODED SETTINGS
# ----------------------------

# If None: download ALL <data type="..."> objects referenced by repomd.xml.
# If set: download only these metadata types.
# For dependency resolution + file requires, you usually need at least: {"primary", "filelists"}.
DOWNLOAD_ONLY_TYPES: Optional[Set[str]] = {"primary", "filelists"}  # e.g. {"primary", "filelists"}

# Verify checksums for downloaded metadata objects if repomd.xml provides them.
VERIFY_CHECKSUMS = True

# Skip downloading a metadata file if it already exists locally AND checksum matches (when available).
SKIP_IF_PRESENT_AND_VALID = True

# Optional proxy support (hard-code or leave None). Example:
# PROXIES = {"https": "http://proxy.company.local:8080"}
PROXIES: Optional[Dict[str, str]] = None

# Set a user agent (some servers care).
USER_AGENT = "repodata-bootstrap-downloader/1.0"


# ----------------------------
# Implementation
# ----------------------------

REPO_NS = {"repo": "http://linux.duke.edu/metadata/repo"}


@dataclass(frozen=True)
class RepomdObject:
    data_type: str
    href: str
    checksum_type: Optional[str]
    checksum_value: Optional[str]


def _build_opener() -> urllib.request.OpenerDirector:
    handlers: List[urllib.request.BaseHandler] = []
    if PROXIES:
        handlers.append(urllib.request.ProxyHandler(PROXIES))
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener


def _http_download(opener: urllib.request.OpenerDirector, url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with opener.open(url) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)


def _hash_file(path: Path, algo: str) -> str:
    algo = algo.lower()
    if algo == "sha256":
        h = hashlib.sha256()
    elif algo == "sha1":
        h = hashlib.sha1()
    elif algo == "md5":
        h = hashlib.md5()
    else:
        raise ValueError(f"Unsupported checksum algo: {algo}")

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_repomd(repomd_path: Path) -> List[RepomdObject]:
    """
    Parse repodata/repomd.xml and return the metadata objects it references.
    """
    tree = ET.parse(str(repomd_path))
    root = tree.getroot()

    objects: List[RepomdObject] = []

    for data in root.findall("repo:data", REPO_NS):
        data_type = (data.get("type") or "").strip()
        loc = data.find("repo:location", REPO_NS)
        href = (loc.get("href") if loc is not None else "") or ""
        href = href.strip()

        checksum_type = None
        checksum_value = None
        chk = data.find("repo:checksum", REPO_NS)
        if chk is not None:
            checksum_type = (chk.get("type") or "").strip() or None
            checksum_value = (chk.text or "").strip() or None

        if data_type and href:
            objects.append(
                RepomdObject(
                    data_type=data_type,
                    href=href,
                    checksum_type=checksum_type,
                    checksum_value=checksum_value,
                )
            )

    if not objects:
        raise RuntimeError(f"No <data> objects found in {repomd_path}")
    return objects


def _should_download(obj: RepomdObject) -> bool:
    if DOWNLOAD_ONLY_TYPES is None:
        return True
    return obj.data_type in DOWNLOAD_ONLY_TYPES


def bootstrap_one_repo(name: str, base_url: str, local_dir: Path, opener: urllib.request.OpenerDirector) -> None:
    base_url = base_url.rstrip("/") + "/"
    local_dir.mkdir(parents=True, exist_ok=True)

    repodata_dir = local_dir / "repodata"
    repodata_dir.mkdir(parents=True, exist_ok=True)

    repomd_url = base_url + "repodata/repomd.xml"
    repomd_path = repodata_dir / "repomd.xml"

    print(f"\n==> [{name}] Downloading repomd.xml")
    print(f"    {repomd_url}")
    _http_download(opener, repomd_url, repomd_path)

    objects = _parse_repomd(repomd_path)
    to_get = [o for o in objects if _should_download(o)]

    print(f"==> [{name}] repomd.xml references {len(objects)} object(s); downloading {len(to_get)}")

    for obj in to_get:
        url = base_url + obj.href.lstrip("/")
        dest = local_dir / Path(obj.href.replace("/", os.sep))

        # Skip if already present and valid
        if dest.exists() and SKIP_IF_PRESENT_AND_VALID:
            if VERIFY_CHECKSUMS and obj.checksum_type and obj.checksum_value:
                try:
                    got = _hash_file(dest, obj.checksum_type)
                    if got.lower() == obj.checksum_value.lower():
                        print(f"    [skip] {obj.data_type}: {obj.href} (already present + checksum ok)")
                        continue
                except ValueError:
                    # unknown hash algo, can't validate; fall through to download
                    pass
            else:
                # no checksum info; assume ok and skip
                print(f"    [skip] {obj.data_type}: {obj.href} (already present)")
                continue

        print(f"    [get ] {obj.data_type}: {obj.href}")
        _http_download(opener, url, dest)

        if VERIFY_CHECKSUMS and obj.checksum_type and obj.checksum_value:
            try:
                got = _hash_file(dest, obj.checksum_type)
            except ValueError:
                print(f"    [warn] {obj.href}: unsupported checksum type '{obj.checksum_type}', not verifying")
                continue

            if got.lower() != obj.checksum_value.lower():
                raise RuntimeError(
                    f"[{name}] Checksum mismatch for {obj.href}\n"
                    f"  expected {obj.checksum_type}={obj.checksum_value}\n"
                    f"  got      {obj.checksum_type}={got}"
                )

    print(f"==> [{name}] Done. Local repodata at: {repodata_dir}")


def main() -> None:
    opener = _build_opener()

    Config.rpm_local_repos = Path(Config.sbom_input_dir, "rpm_repos")

    REPOS = [
        {
            "name": "pgdg18-rhel9-x86_64",
            "base_url": "https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-9-x86_64/",
            "local_dir": Path(Config.rpm_local_repos, "pgdg18-rhel9-x86_64"),
        },
        {
            "name": "ubi9-baseos-x86_64",
            "base_url": "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/",
            "local_dir": Path(Config.rpm_local_repos, "ubi9-baseos-x86_64"),
        },
        {
            "name": "ubi9-appstream-x86_64",
            "base_url": "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/appstream/os/",
            "local_dir": Path(Config.rpm_local_repos, "ubi9-appstream-x86_64"),
        },
        # Optional but often helpful:
        {
            "name": "ubi9-codeready-builder-x86_64",
            "base_url": "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/os/",
            "local_dir": Path(Config.rpm_local_repos, "ubi9-codeready-builder-x86_64"),
        },
    ]

    for r in REPOS:
        name = r["name"]
        base_url = r["base_url"]
        local_dir = Path(r["local_dir"])
        bootstrap_one_repo(name, base_url, local_dir, opener)


if __name__ == "__main__":
    main()