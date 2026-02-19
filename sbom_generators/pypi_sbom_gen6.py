#!/usr/bin/env python3
"""
Generate a CycloneDX (specVersion 1.5) SBOM for PyPI packages listed in requirements.txt,
using the PyPI JSON API (https://pypi.org/pypi).

Prereqs:
  pip install requests packaging
"""
import shutil
import subprocess
from pathlib import Path

from configuration import Configuration as Config
import json
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion


# REQUIREMENTS_TXT_PATH = "requirements.txt"
# OUTPUT_SBOM_PATH = "sbom.json"

# Target Python version compatibility
TARGET_PYTHON_FULL_VERSION = "3.12.10"  # e.g. "3.11.8"
TARGET_PYTHON_VERSION = ".".join(TARGET_PYTHON_FULL_VERSION.split(".")[:2])  # "3.11"

# Root "application" component used as the SBOM metadata.component
ROOT_COMPONENT_NAME = "pypi-requirements"
ROOT_COMPONENT_GROUP = "com.lmco.crt"
ROOT_COMPONENT_VERSION = "1.0.0"

# Version selection behavior
ALLOW_PRERELEASES = False
REQUEST_TIMEOUT_SECONDS = 30
MAX_HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF_SECONDS = 1.5

# Optional: if you want dependency marker evaluation to target a specific platform,
# override these. By default, current environment values are used (except python version).
# Examples:
#   TARGET_ENV_OVERRIDES = {"sys_platform": "win32", "platform_system": "Windows"}
TARGET_ENV_OVERRIDES: Dict[str, str] = {}


# =============================================================================
# Helpers
# =============================================================================

PYPI_BASE = "https://pypi.org/pypi"


def pep503_normalize(name: str) -> str:
    # PEP 503 normalization (rough): lowercase and replace runs of [-_.] with '-'
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{pep503_normalize(name)}@{version}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# -------------------------------------------------------------------
# uv bootstrap + requirements.txt generation
# -------------------------------------------------------------------
def _run_uv(args: list[str]) -> None:
    """
    Run uv either via the uv executable (preferred) or as `python -m uv` fallback.
    """
    uv_exe = shutil.which("uv")
    if uv_exe:
        subprocess.run([uv_exe, *args], check=True)
        return

    # Fallback: if `uv` was installed in this interpreter but Scripts/ isn't on PATH.
    subprocess.run([sys.executable, "-m", "uv", *args], check=True)


def ensure_uv_installed() -> None:
    """
    1) Pip install uv if not present.
    """
    try:
        _run_uv(["--version"])
        return
    except Exception:
        # Not installed or not runnable -> install via pip into the current interpreter env
        subprocess.run([sys.executable, "-m", "pip", "install", "uv"], check=True)
        # Re-check (fail fast if something still isn't right)
        _run_uv(["--version"])


def generate_requirements_txt() -> None:
    """
    2) Execute:
       uv pip compile --python {python_version} -o requirements.txt requirements.in
    """
    if not Config.requirements_in_file_path.exists():
        raise FileNotFoundError(f"Missing input file: {Config.requirements_in_file_path.resolve()}")

    ensure_uv_installed()

    _run_uv([
        "pip", "compile",
        "--python", TARGET_PYTHON_VERSION,
        "-o", str(Config.requirements_txt_file_path),
        str(Config.requirements_in_file_path),
    ])


def build_target_environment() -> Dict[str, str]:
    env = default_environment()
    env["python_version"] = TARGET_PYTHON_VERSION
    env["python_full_version"] = TARGET_PYTHON_FULL_VERSION
    env.update(TARGET_ENV_OVERRIDES)
    # Marker evaluation sometimes references "extra"; set blank by default
    env.setdefault("extra", "")
    return env


TARGET_ENV = build_target_environment()


def http_get_json(url: str) -> Dict[str, Any]:
    last_exc: Optional[Exception] = None
    for attempt in range(1, MAX_HTTP_RETRIES + 1):
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS, headers={"Accept": "application/json"})
            if resp.status_code == 404:
                raise RuntimeError(f"PyPI returned 404 for {url}")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            last_exc = e
            if attempt < MAX_HTTP_RETRIES:
                time.sleep(HTTP_RETRY_BACKOFF_SECONDS * attempt)
            else:
                break
    raise RuntimeError(f"Failed to GET {url}: {last_exc}")


def fetch_project_json(project: str) -> Dict[str, Any]:
    # Latest project JSON
    return http_get_json(f"{PYPI_BASE}/{pep503_normalize(project)}/json")


def fetch_project_version_json(project: str, version: str) -> Dict[str, Any]:
    # Version-specific JSON (ensures requires_dist and info match chosen version)
    return http_get_json(f"{PYPI_BASE}/{pep503_normalize(project)}/{version}/json")


def is_python_compatible(requires_python: Optional[str]) -> bool:
    """
    requires_python is a PEP 440 specifier string, e.g. ">=3.8".
    If missing, assume compatible.
    """
    if not requires_python:
        return True
    try:
        spec = SpecifierSet(requires_python)
        return spec.contains(TARGET_PYTHON_FULL_VERSION, prereleases=True) or spec.contains(
            TARGET_PYTHON_VERSION, prereleases=True
        )
    except Exception:
        # If malformed, be conservative and treat as incompatible
        return False


def any_file_compatible(files: List[Dict[str, Any]]) -> bool:
    """
    For a release version, PyPI provides a list of files, each may have requires_python.
    If any file is compatible, accept that release.
    """
    if not files:
        return False
    for f in files:
        if is_python_compatible(f.get("requires_python")):
            return True
    # If none of the files declare requires_python, treat as compatible (best-effort)
    if all(f.get("requires_python") in (None, "") for f in files):
        return True
    return False


def choose_best_version(project: str, spec: SpecifierSet) -> str:
    """
    Choose the highest version that:
      - satisfies the incoming specifier (from requirements or parent dependency)
      - is compatible with TARGET_PYTHON_* based on PyPI release files requires_python
      - respects ALLOW_PRERELEASES
    """
    proj = fetch_project_json(project)
    releases: Dict[str, List[Dict[str, Any]]] = proj.get("releases", {})

    candidates: List[Version] = []
    for ver_str in releases.keys():
        try:
            v = Version(ver_str)
        except InvalidVersion:
            continue
        if not ALLOW_PRERELEASES and v.is_prerelease:
            continue
        if not spec.contains(ver_str, prereleases=ALLOW_PRERELEASES):
            continue
        if any_file_compatible(releases.get(ver_str, [])):
            candidates.append(v)

    if not candidates:
        raise RuntimeError(
            f"No compatible version found for '{project}' matching '{spec}' for Python {TARGET_PYTHON_FULL_VERSION}"
        )

    candidates.sort(reverse=True)
    return str(candidates[0])


def parse_requirements_file(path: Path) -> List[Requirement]:
    """
    Reads requirements.txt and returns parsed top-level Requirement objects.
    Skips:
      - blank lines / comments
      - -r includes
      - non-PEP508 lines (logs warnings)
    """
    reqs: List[Requirement] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f.readlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r") or line.startswith("--requirement"):
                print(f"[WARN] Skipping nested requirement include: {line}")
                continue
            if line.startswith("-") and "://" in line:
                print(f"[WARN] Skipping URL/vcs requirement (not supported): {line}")
                continue
            try:
                reqs.append(Requirement(line))
            except Exception:
                print(f"[WARN] Skipping unparseable requirement line: {line}")
    return reqs


def marker_allows(requirement: Requirement) -> bool:
    """
    Evaluate environment markers (e.g. python_version, sys_platform).
    If no marker, allow.
    """
    if requirement.marker is None:
        return True
    try:
        return bool(requirement.marker.evaluate(environment=TARGET_ENV))
    except Exception:
        # If marker evaluation fails, be conservative and include it.
        return True


def requirement_to_specifier(req: Requirement) -> SpecifierSet:
    """
    If no version spec is provided, treat as "any version".
    """
    if req.specifier is None or str(req.specifier).strip() == "":
        return SpecifierSet("")
    return req.specifier


def extract_license_name(info: Dict[str, Any]) -> Optional[str]:
    """
    Try to pull a human-friendly license name from:
      - info["license"]
      - classifiers starting with "License ::"
    """
    lic = (info.get("license") or "").strip()
    if lic and lic.upper() not in {"UNKNOWN", "UNLICENSED", "NONE"}:
        return lic

    classifiers = info.get("classifiers") or []
    for c in classifiers:
        if isinstance(c, str) and c.startswith("License ::"):
            # Typically "License :: OSI Approved :: MIT License"
            parts = [p.strip() for p in c.split("::") if p.strip()]
            if parts:
                return parts[-1]
    return None


def extract_external_references(info: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Append *all* project_urls to externalReferences.

    - Picks one "best" URL to label as type "vcs" (case-insensitive key matching + URL heuristic).
    - Other URLs are labeled as:
        - "documentation" (docs/homepage-like keys)
        - "issue-tracker" (bug/issue/tracker-like keys or URL hints)
        - "website" (fallback)
    - De-dupes by (type, url).
    """
    refs: List[Dict[str, str]] = []

    project_urls = info.get("project_urls") or {}
    items: List[Tuple[str, str]] = []

    if isinstance(project_urls, dict):
        for k, v in project_urls.items():
            if isinstance(v, str) and v.strip():
                items.append((str(k), v.strip()))

    # Optional: include legacy "home_page" if present (not part of project_urls but often useful)
    home_page = info.get("home_page")
    if isinstance(home_page, str) and home_page.strip():
        items.append(("home_page", home_page.strip()))

    def key_lc(key: str) -> str:
        return key.strip().lower()

    def is_repo_like(url: str) -> bool:
        u = url.lower()
        return (
            "github.com" in u
            or "gitlab" in u
            or "bitbucket" in u
            or u.endswith(".git")
            or u.startswith("git+http://")
            or u.startswith("git+https://")
        )

    def is_issue_like(key: str, url: str) -> bool:
        k = key_lc(key)
        u = url.lower()
        return (
            "bug" in k
            or "issue" in k
            or "tracker" in k
            or "bug tracker" in k
            or "/issues" in u
            or "bugs" in u
        )

    def is_doc_like(key: str) -> bool:
        k = key_lc(key)
        return (
            "documentation" in k
            or k == "docs"
            or "doc" == k
            or "homepage" in k
            or k == "home"
        )

    # ---- pick the single best VCS URL ----
    vcs_key_tokens = (
        "repository", "repo", "source", "source code", "code", "scm", "vcs", "github", "gitlab", "bitbucket"
    )

    best_vcs_url: Optional[str] = None
    best_score = -1

    for k, u in items:
        kl = key_lc(k)
        repo_like = is_repo_like(u)

        # score: prefer keys that indicate repo + URLs that look like repos
        score = 0
        if any(tok in kl for tok in vcs_key_tokens):
            score += 10
        if repo_like:
            score += 5
        # slight boost if key explicitly names a forge
        if "github" in kl or "gitlab" in kl or "bitbucket" in kl:
            score += 2

        # Only consider as VCS if it actually looks repo-like;
        # otherwise it's likely a homepage or tracker even if key says "Repository".
        if repo_like and score > best_score:
            best_score = score
            best_vcs_url = u

    # ---- append all project URLs with appropriate types ----
    for k, u in items:
        if best_vcs_url and u == best_vcs_url:
            ref_type = "vcs"
        elif is_doc_like(k):
            ref_type = "documentation"
        elif is_issue_like(k, u):
            ref_type = "issue-tracker"
        else:
            ref_type = "website"

        refs.append({"type": ref_type, "url": u})

    # ---- de-dupe by (type, url) ----
    seen = set()
    uniq: List[Dict[str, str]] = []
    for r in refs:
        key = (r.get("type", ""), r.get("url", ""))
        if key not in seen:
            seen.add(key)
            uniq.append(r)

    return uniq


# =============================================================================
# Resolver + SBOM model
# =============================================================================

@dataclass(frozen=True)
class ResolvedPackage:
    name: str
    version: str


class SbomBuilder:
    def __init__(self) -> None:
        self.resolved: Dict[str, ResolvedPackage] = {}  # normalized_name -> ResolvedPackage
        self.dependency_edges: Dict[str, Set[str]] = {}  # parent_ref -> set(child_ref)
        self.component_info_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def resolve_requirement(self, req: Requirement) -> Optional[ResolvedPackage]:
        """
        Resolve a requirement to a concrete name+version, respecting:
          - environment markers
          - version specifiers
          - Python compatibility
        """
        if not marker_allows(req):
            return None

        name_norm = pep503_normalize(req.name)
        spec = requirement_to_specifier(req)

        # If already resolved, ensure it satisfies the new spec
        if name_norm in self.resolved:
            existing = self.resolved[name_norm]
            if spec and not spec.contains(existing.version, prereleases=ALLOW_PRERELEASES):
                print(
                    f"[WARN] Version conflict for {req.name}: already pinned to {existing.version} "
                    f"but new constraint is '{spec}'. Keeping {existing.version}."
                )
            return existing

        # Prefer exact pin if present (==)
        pinned_version: Optional[str] = None
        for sp in spec:
            if sp.operator == "==":
                pinned_version = sp.version
                break

        if pinned_version:
            # Validate Python compatibility for this pinned version
            vjson = fetch_project_version_json(req.name, pinned_version)
            info = vjson.get("info", {})
            # Check requires_python from info if present, else release files
            if not is_python_compatible(info.get("requires_python")):
                raise RuntimeError(
                    f"Pinned version {req.name}=={pinned_version} is not compatible with Python {TARGET_PYTHON_FULL_VERSION} "
                    f"(requires_python={info.get('requires_python')})"
                )
            resolved = ResolvedPackage(req.name, pinned_version)
        else:
            best = choose_best_version(req.name, spec)
            resolved = ResolvedPackage(req.name, best)

        self.resolved[name_norm] = resolved
        return resolved

    def get_component_json(self, pkg: ResolvedPackage) -> Dict[str, Any]:
        key = (pep503_normalize(pkg.name), pkg.version)
        if key in self.component_info_cache:
            return self.component_info_cache[key]

        vjson = fetch_project_version_json(pkg.name, pkg.version)
        self.component_info_cache[key] = vjson
        return vjson

    def add_edge(self, parent_ref: str, child_ref: str) -> None:
        self.dependency_edges.setdefault(parent_ref, set()).add(child_ref)

    def resolve_transitives(self, roots: List[ResolvedPackage]) -> None:
        """
        BFS over dependencies using requires_dist from each chosen version.
        """
        queue: List[ResolvedPackage] = list(roots)
        seen: Set[Tuple[str, str]] = set()

        while queue:
            pkg = queue.pop(0)
            pkg_key = (pep503_normalize(pkg.name), pkg.version)
            if pkg_key in seen:
                continue
            seen.add(pkg_key)

            vjson = self.get_component_json(pkg)
            info = vjson.get("info", {})
            requires_dist = info.get("requires_dist") or []

            parent_ref = purl(pkg.name, pkg.version)

            for dep_str in requires_dist:
                if not isinstance(dep_str, str):
                    continue
                try:
                    dep_req = Requirement(dep_str)
                except Exception:
                    print(f"[WARN] Could not parse dependency '{dep_str}' for {pkg.name}=={pkg.version}")
                    continue

                # Skip extras requirements unless they apply by marker (extra == ...)
                if not marker_allows(dep_req):
                    continue

                dep_resolved = self.resolve_requirement(dep_req)
                if dep_resolved is None:
                    continue

                child_ref = purl(dep_resolved.name, dep_resolved.version)
                self.add_edge(parent_ref, child_ref)

                # Continue BFS
                queue.append(dep_resolved)

    def build_components(self) -> List[Dict[str, Any]]:
        components: List[Dict[str, Any]] = []

        # Stable order for output
        pkgs = sorted(self.resolved.values(), key=lambda p: (pep503_normalize(p.name), Version(p.version)))

        for pkg in pkgs:
            vjson = self.get_component_json(pkg)
            info = vjson.get("info", {}) or {}

            comp: Dict[str, Any] = {
                "type": "library",
                "group": "pypi",
                "name": pep503_normalize(pkg.name),
                "version": pkg.version,
                "purl": purl(pkg.name, pkg.version),
                "bom-ref": purl(pkg.name, pkg.version),
            }

            # Prefer summary as a short "description"
            desc = (info.get("summary") or "").strip() or (info.get("description") or "").strip()
            if desc:
                comp["description"] = desc

            lic_name = extract_license_name(info)
            if lic_name:
                comp["licenses"] = [{"license": {"name": lic_name}}]

            ext_refs = extract_external_references(info)
            if ext_refs:
                comp["externalReferences"] = ext_refs

            components.append(comp)

        return components

    def build_dependencies_section(self, root_depends_on: List[str]) -> List[Dict[str, Any]]:
        """
        CycloneDX dependencies:
          - include the root component dependsOn top-levels
          - include each component with its own dependsOn list (transitives)
        """
        deps: List[Dict[str, Any]] = []

        # Root entry
        deps.append(
            {
                "ref": purl(ROOT_COMPONENT_NAME, ROOT_COMPONENT_VERSION),
                "dependsOn": sorted(set(root_depends_on)),
            }
        )

        # Per-package entries
        # Ensure every resolved component has an entry, even if no deps.
        all_refs = [purl(p.name, p.version) for p in self.resolved.values()]
        for ref in sorted(set(all_refs)):
            children = sorted(self.dependency_edges.get(ref, set()))
            deps.append({"ref": ref, "dependsOn": children})

        return deps


def main() -> None:
    Config.requirements_txt_file_path = Path(Config.sbom_input_dir, Config.requirements_txt_file_name)
    Config.requirements_in_file_path = Path(Config.sbom_input_dir, Config.requirements_in_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    generate_requirements_txt()

    # 1) Read top-level requirements
    top_level_requirements = parse_requirements_file(Config.requirements_txt_file_path)
    if not top_level_requirements:
        raise RuntimeError(f"No valid requirements found in {Config.requirements_txt_file_path}")

    builder = SbomBuilder()

    # 2) Resolve top-level packages to concrete versions
    top_level_pkgs: List[ResolvedPackage] = []
    for req in top_level_requirements:
        resolved = builder.resolve_requirement(req)
        if resolved is not None:
            top_level_pkgs.append(resolved)

    # 3) Resolve transitives
    builder.resolve_transitives(top_level_pkgs)

    # 4) Build SBOM structure
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utc_now_iso(),
            "component": {
                "type": "library",
                "name": ROOT_COMPONENT_NAME,
                "group": ROOT_COMPONENT_GROUP,
                "version": ROOT_COMPONENT_VERSION,
                "bom-ref": purl(ROOT_COMPONENT_NAME, ROOT_COMPONENT_VERSION),
                "purl": purl(ROOT_COMPONENT_NAME, ROOT_COMPONENT_VERSION),
            },
        },
        "components": builder.build_components(),
    }

    root_depends_on = [purl(p.name, p.version) for p in top_level_pkgs]
    sbom["dependencies"] = builder.build_dependencies_section(root_depends_on)

    # 5) Write output
    with open(Config.sbom_output_file_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    print(f"[OK] Wrote SBOM to: {Config.sbom_output_file_path}")
    print(f"[OK] Target Python: {TARGET_PYTHON_FULL_VERSION}")
    print(f"[OK] Top-level packages: {len(top_level_pkgs)}")
    print(f"[OK] Total resolved packages (incl. transitives): {len(builder.resolved)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)