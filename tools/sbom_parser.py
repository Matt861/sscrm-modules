#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse
import requests
from configuration import Configuration as Config
from models.component import Component, ComponentStore


# --- GitHub URL matching / normalization ---

# Allowed input formats:
#   https://github.com/owner/repo
#   http://github.com/owner/repo
#   https://github.com/owner/repo.git
#   https://gitbox.com/
#   git@github.com:owner/repo.git
#
# Output format:
#   https://github.com/owner/repo

_GITBOX_HOSTS = {"gitbox.apache.org"}
_GITHUB_HOSTS = {"github.com"}


# def _normalize_github_repo_url(url: str) -> Optional[str]:
#     """
#     Normalize GitHub repo URLs to: https://github.com/<owner>/<repo>
#     """
#     if not url:
#         return None
#     url = _ensure_https(url.strip())
#     p = urlparse(url)
#     host = (p.netloc or "").lower()
#     if host != "github.com":
#         return None
#
#     parts = [x for x in p.path.split("/") if x]
#     if len(parts) < 2:
#         return None
#
#     owner, repo = parts[0], _strip_dot_git(parts[1])
#     return f"https://github.com/{owner}/{repo}"


def _strip_dot_git(s: str) -> str:
    return s[:-4] if s.lower().endswith(".git") else s


def _ensure_https_url(url: str) -> str:
    """
    Force https scheme for parseable URLs (http/https/git).
    Leaves scp-like forms alone (git@github.com:owner/repo.git).
    """
    p = urlparse(url)
    if p.scheme in ("http", "https", "git", ""):
        scheme = "https" if p.scheme in ("http", "git", "") else p.scheme
        p = p._replace(scheme=scheme)
        return urlunparse(p)
    return url


def _strip_scm_prefix(url: str) -> str:
    """
    CycloneDX / Maven SCM strings often look like:
      scm:git:git://github.com/org/repo.git
      scm:git:git@github.com:org/repo.git
    We remove leading scm:*:* prefixes.
    """
    s = url.strip()
    while s.lower().startswith("scm:"):
        parts = s.split(":", 2)
        if len(parts) < 3:
            break
        s = parts[2].lstrip()
    return s


def _parse_github_scp_like(url: str) -> Optional[str]:
    """
    Handle scp-like GitHub URLs:
      git@github.com:owner/repo.git
      github.com:owner/repo.git
    """
    s = url.strip()

    if s.lower().startswith("git@github.com:"):
        tail = s[len("git@github.com:") :]
        parts = [p for p in tail.split("/") if p]
        if len(parts) >= 2:
            owner, repo = parts[0], _strip_dot_git(parts[1])
            return f"https://github.com/{owner}/{repo}"
        return None

    if s.lower().startswith("github.com:"):
        tail = s[len("github.com:") :]
        parts = [p for p in tail.split("/") if p]
        if len(parts) >= 2:
            owner, repo = parts[0], _strip_dot_git(parts[1])
            return f"https://github.com/{owner}/{repo}"
        return None

    return None


def _normalize_github_httpish(url: str, timeout: int = 15) -> Optional[str]:
    """
    Normalize parseable GitHub URLs:
      https://github.com/owner/repo
      git://github.com/owner/repo.git
      ssh://git@github.com/owner/repo.git
    """
    s = url.strip()
    if not s:
        return None

    p = urlparse(s)
    host = (p.hostname or "").lower()
    if host != "github.com":
        return None

    parts = [x for x in (p.path or "").split("/") if x]
    if len(parts) < 2:
        return None

    owner, repo = parts[0], _strip_dot_git(parts[1])

    repo_url = f"https://github.com/{owner}/{repo}"

    final = _resolve_final_url(repo_url, timeout=timeout)
    if not final:
        return None
    return repo_url


def _looks_like_gitbox_or_gitwip(url: str) -> bool:
    """
    URLs that commonly redirect to GitHub mirrors:
      - *gitbox* hosts
      - git-wip-us.apache.org (older ASF infrastructure)
    """
    try:
        s = _strip_scm_prefix(url)
        p = urlparse(_ensure_https_url(s))
        host = (p.hostname or p.netloc or "").lower()
        return ("gitbox" in host) or ("git-wip-us.apache.org" in host)
    except Exception:
        return False


def _maybe_rewrite_gitwip_query_to_github(url: str) -> Optional[str]:
    """
    Handle ASF git-wip style:
      https://git-wip-us.apache.org/repos/asf?p=commons-math.git
    Deterministic best-effort rewrite to:
      https://github.com/apache/commons-math

    Returns None if URL isn't git-wip style or doesn't include p=<repo>.
    """
    try:
        s = _strip_scm_prefix(url.strip())
        p = urlparse(_ensure_https_url(s))
        host = (p.hostname or "").lower()
        if host != "git-wip-us.apache.org":
            return None

        # Expect query param p=<repo>.git
        q = p.query or ""
        # very small parser to avoid importing parse_qs
        for part in q.split("&"):
            if part.startswith("p="):
                repo = part[2:].strip()
                repo = _strip_dot_git(repo)
                if repo:
                    return f"https://github.com/apache/{repo}"
        return None
    except Exception:
        return None


@lru_cache(maxsize=4096)
def _resolve_final_url(url: str, *, timeout: int = 15) -> Optional[str]:
    """
    Follow redirects and return the final resolved URL.
    Cached to avoid repeated network calls for the same input URL.
    """
    if url == "https://github.com/paulmillr/async-each":
        print('test')
    if not url:
        return None

    url = url.strip()
    if not url:
        return None

    url = _ensure_https_url(url)

    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        if r.status_code >= 400 or not r.url:
            r = requests.get(url, allow_redirects=True, timeout=timeout)
        if r.status_code == 404 or not r.url:
            return None
        final = (r.url or "").strip()
        return final or None
    except requests.RequestException:
        return None


def normalize_vcs_url_to_github(
    url: str,
    *,
    follow_redirects_for_mirrors: bool = True,
    timeout: int = 15,
) -> Optional[str]:
    """
    Normalize various VCS URL formats to a GitHub repo URL.

    Supported:
      - git://github.com/owner/repo.git
      - scm:git:git://github.com/owner/repo.git
      - scm:git:git@github.com:owner/repo.git
      - https://github.com/owner/repo
      - ssh://git@github.com/owner/repo.git
      - https://git-wip-us.apache.org/repos/asf?p=<repo>.git  (rewritten or redirect-resolved)

    Rule: Non-GitHub final URLs return None (GitLab/Bitbucket/etc).
    """
    if not url or not str(url).strip():
        return None

    s = _strip_scm_prefix(str(url).strip())

    # 0) Deterministic rewrite for git-wip-us.apache.org?p=<repo>.git
    # (fast, no network, matches your example)
    rew = _maybe_rewrite_gitwip_query_to_github(s)
    if rew:
        final = _resolve_final_url(rew, timeout=timeout)
        if not final:
            return None
        return rew

    # 1) scp-like GitHub forms (git@github.com:owner/repo.git)
    scp = _parse_github_scp_like(s)
    if scp:
        final = _resolve_final_url(scp, timeout=timeout)
        if not final:
            return None
        return scp

    # 2) Parseable GitHub URLs (https/git/ssh)
    gh = _normalize_github_httpish(s, timeout=timeout)
    if gh:
        if gh == "https://github.com/paulmillr/async-each":
            print('test')
        final = _resolve_final_url(gh, timeout=timeout)
        if not final:
            return None
        return gh

    # 3) Mirror-ish hosts: follow redirects and only accept GitHub final URL
    if follow_redirects_for_mirrors and _looks_like_gitbox_or_gitwip(s):
        final = _resolve_final_url(s, timeout=timeout)
        if not final:
            return None

        final = _strip_scm_prefix(final)

        scp2 = _parse_github_scp_like(final)
        if scp2:
            return scp2

        gh2 = _normalize_github_httpish(final, timeout=timeout)
        return gh2  # None if not GitHub

    # 4) Everything else (gitlab/bitbucket/unknown) => None
    return None


# --- CycloneDX JSON helpers ---

def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    return str(v).strip() or None


def _component_group_like(c: dict[str, Any]) -> Optional[str]:
    # Maven SBOMs often use "group"; some producers use "namespace"
    return _safe_str(c.get("group")) or _safe_str(c.get("namespace"))


def _bom_ref(c: dict[str, Any]) -> Optional[str]:
    # CycloneDX JSON commonly uses "bom-ref"; be tolerant of "bomRef"
    return _safe_str(c.get("bom-ref")) or _safe_str(c.get("bomRef"))


def extract_urls(component: dict[str, Any]) -> tuple[list[str], list[str]]:
    vcs_urls: list[str] = []
    other_urls: list[str] = []

    ext_refs = component.get("externalReferences")
    if not isinstance(ext_refs, list):
        return vcs_urls, other_urls

    for ref in ext_refs:
        if not isinstance(ref, dict):
            continue
        ref_type = (ref.get("type") or "").strip().lower()
        url = _safe_str(ref.get("url"))
        if not url:
            continue

        if ref_type == "vcs":
            vcs_urls.append(url)
        else:
            other_urls.append(url)

    return vcs_urls, other_urls


def extract_license_ids_or_names(component: dict[str, Any]) -> list[str]:
    """
    Extract license identifiers/names from a CycloneDX component.

    Supports typical CycloneDX JSON patterns, e.g.:
      "licenses": [
        { "license": { "id": "Apache-2.0", "name": "Apache License 2.0" } }
      ]
    and expressions:
      "licenses": [
        { "expression": "MIT OR Apache-2.0" }
      ]

    Returns:
      A deduped list of strings. Prefers SPDX id when present, else name,
      else expression.
    """
    results: list[str] = []

    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return results

    for item in licenses:
        if not isinstance(item, dict):
            continue

        # CycloneDX license expression form
        expr = _safe_str(item.get("expression"))
        if expr:
            results.append(expr)
            continue

        # CycloneDX nested license form
        lic = item.get("license")
        if isinstance(lic, dict):
            lic_id = _safe_str(lic.get("id"))
            lic_name = _safe_str(lic.get("name"))
            # Prefer id; fall back to name
            results.append(lic_id or lic_name or "")
            continue

        # Some producers may flatten fields directly
        lic_id = _safe_str(item.get("id"))
        lic_name = _safe_str(item.get("name"))
        if lic_id or lic_name:
            results.append(lic_id or lic_name or "")
            continue

    # Clean + dedupe while preserving order
    cleaned: list[str] = []
    seen: set[str] = set()
    for r in results:
        r = (r or "").strip()
        if not r:
            continue
        if r in seen:
            continue
        seen.add(r)
        cleaned.append(r)

    return cleaned


def find_repo_url(component: dict[str, Any], timeout: int = 15) -> Optional[str]:
    vcs_urls, other_urls = extract_urls(component)

    for u in vcs_urls:
        if u == "https://github.com/paulmillr/async-each":
            print('test')
        norm = normalize_vcs_url_to_github(u, follow_redirects_for_mirrors=True)
        if norm:
            return norm

    for u in other_urls:
        if u == "https://github.com/paulmillr/async-each":
            print('test')
        norm = _normalize_github_httpish(u, timeout=timeout)
        if norm:
            return norm

    return None


def _is_same_as_top_level(comp: dict[str, Any], top_level: dict[str, Any]) -> bool:
    """
    Determine whether `comp` in the components[] list is the same as metadata.component.

    Prefer bom-ref match; fall back to (group/namespace, name, version) match.
    """
    if not isinstance(top_level, dict) or not isinstance(comp, dict):
        return False

    top_ref = _bom_ref(top_level)
    comp_ref = _bom_ref(comp)
    if top_ref and comp_ref and top_ref == comp_ref:
        return True

    # Fallback match (best effort)
    return (
        _component_group_like(comp) == _component_group_like(top_level)
        and _safe_str(comp.get("name")) == _safe_str(top_level.get("name"))
        and _safe_str(comp.get("version")) == _safe_str(top_level.get("version"))
    )


# --- CycloneDX direct-dependency helpers ---

def _dependency_ref(d: dict[str, Any]) -> Optional[str]:
    # CycloneDX dependency objects commonly use "ref"; be tolerant of "bom-ref"/"bomRef"
    return _safe_str(d.get("ref")) or _bom_ref(d)


def _dependency_children(d: dict[str, Any]) -> list[str]:
    kids = d.get("dependsOn")
    if not isinstance(kids, list):
        return []
    out: list[str] = []
    for k in kids:
        s = _safe_str(k)
        if s:
            out.append(s)
    return out


def _compute_direct_dependency_refs(
    data: dict[str, Any],
    *,
    top_level: dict[str, Any],
) -> set[str]:
    """
    Return the set of bom-refs that are direct/top-level dependencies of the SBOM.

    Primary strategy:
      - Find metadata.component's bom-ref (top_ref)
      - In data["dependencies"], find the entry whose ref == top_ref
      - direct deps are that entry's dependsOn refs

    Fallback strategies:
      - If top_ref missing, try to derive it by matching metadata.component against components[]
      - If still unknown, infer "root" refs (refs that are not depended-on by anyone) and:
          - if exactly one root exists, treat its dependsOn as direct deps
          - otherwise return empty set (ambiguous)
    """
    deps = data.get("dependencies")
    if not isinstance(deps, list) or not deps:
        return set()

    # Build dep_map: ref -> dependsOn[]
    dep_map: dict[str, list[str]] = {}
    all_refs: set[str] = set()
    all_children: set[str] = set()

    for d in deps:
        if not isinstance(d, dict):
            continue
        ref = _dependency_ref(d)
        if not ref:
            continue
        kids = _dependency_children(d)
        dep_map[ref] = kids
        all_refs.add(ref)
        all_children.update(kids)

    # Try to get top_ref directly from metadata.component
    top_ref = _bom_ref(top_level)

    # If metadata.component has no bom-ref, try to find matching component in components[] and use its bom-ref
    if not top_ref:
        comps = data.get("components")
        if isinstance(comps, list) and top_level:
            for c in comps:
                if not isinstance(c, dict):
                    continue
                if _is_same_as_top_level(c, top_level):
                    top_ref = _bom_ref(c)
                    if top_ref:
                        break

    # Primary: metadata.component ref -> dependsOn
    if top_ref and top_ref in dep_map:
        return set(dep_map.get(top_ref, []) or [])

    # Fallback: infer roots (refs not depended on by any other)
    roots = list(all_refs - all_children)
    if len(roots) == 1:
        return set(dep_map.get(roots[0], []) or [])

    # Ambiguous or cannot determine
    return set()


def parse_sbom(sbom_path: Path, timeout: int = 15) -> list[Component]:
    data = json.loads(sbom_path.read_text(encoding="utf-8"))

    # Identify the top-level (project) component, but DO NOT yield/create a Component from it.
    top_level = data.get("metadata", {}).get("component")
    if not isinstance(top_level, dict):
        top_level = {}

    # compute direct/top-level dependency refs from the SBOM dependency graph
    direct_refs = _compute_direct_dependency_refs(data, top_level=top_level)

    components: list[Component] = []

    comps = data.get("components")
    if isinstance(comps, list):
        for c in comps:
            if not isinstance(c, dict):
                continue

            # Skip if this component is the same as metadata.component
            if top_level and _is_same_as_top_level(c, top_level):
                continue

            group = _component_group_like(c)
            name = _safe_str(c.get("name")) or ""

            # used to decide direct vs transitive
            comp_ref = _bom_ref(c)
            is_direct = bool(comp_ref and comp_ref in direct_refs)

            components.append(
                Component(
                    name=name,
                    group=group,
                    version=_safe_str(c.get("version")),
                    publisher=_safe_str(c.get("publisher")),
                    description=_safe_str(c.get("description")),
                    licenses=extract_license_ids_or_names(c),
                    repo_url=find_repo_url(c, timeout=timeout),
                    is_direct=is_direct,
                )
            )

    return components


def sibling_missing_repo_path(full_components_path: Path) -> Path:
    stem = full_components_path.stem
    suffix = full_components_path.suffix
    return full_components_path.with_name(f"{stem}.missing-repo{suffix}")


def main() -> None:
    if not Config.sbom_output_file_path.exists():
        print(f"ERROR: sbom file not found: {Config.sbom_output_file_path}")
        sys.exit()

    components = parse_sbom(Config.sbom_output_file_path, timeout=Config.requests_timeout)

    if Config.sbom_parser_dedupe:
        seen: set[tuple[Optional[str], str, Optional[str]]] = set()
        deduped: list[Component] = []
        for c in components:
            key = (c.group, c.name, c.version)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(c)
        components = deduped

    # Build a store (handy for callers)
    Config.component_store = ComponentStore()
    Config.component_store.add_components(components)

    print(f"Parsed {len(Config.component_store.get_all_components())} components")


if __name__ == "__main__":
    main()
