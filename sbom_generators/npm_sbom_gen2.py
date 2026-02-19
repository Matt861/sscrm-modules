#!/usr/bin/env python3
"""
Registry-based CycloneDX SBOM generator for npm projects (Dependency-Track friendly).

- Reads dependencies from package.json (and optional devDependencies).
- Does NOT run npm and does NOT use cyclonedx tools.
- Queries package data from https://registry.npmjs.org/ for:
  - dependency relationships (if no package-lock.json)
  - enrichment (description, license, homepage/repo/bugs, tarball)
- Emits CycloneDX JSON in the same DT-approved structure you used for PyPI/Go:
  {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:...",
    "version": 1,
    "metadata": { "timestamp": "...", "component": {...} },
    "components": [...],
    "dependencies": [...]
  }

Rules:
- metadata.component is NOT duplicated into components[]
- Only dependencies are in components[]
- Only metadata.component has a hard-coded "group"
- For scoped packages "@scope/name": component group="scope", name="name"
"""

from configuration import Configuration as Config
import json
import re
import sys
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote


# CycloneDX version accepted by Dependency-Track (matches your other generators)
SBOM_SPEC_VERSION = "1.5"

# Root (metadata.component) fields
METADATA_COMPONENT_TYPE = "library"

# Include devDependencies?
INCLUDE_DEV_DEPENDENCIES = True

# Prefer exact versions from package-lock.json if present (recommended)
USE_PACKAGE_LOCK_IF_PRESENT = True

# Registry base URL (can be changed to an internal registry)
REGISTRY_BASE = "https://registry.npmjs.org"

# Networking
HTTP_TIMEOUT_SECONDS = 30
USER_AGENT = "sbom-npm-registry/1.0"

# Debug
PRINT_DEBUG = False

# PURL formatting:
# The purl spec commonly encodes scoped '@' as '%40'. You previously asked to keep '@' in output.
# So by default we DO NOT percent-encode '@' in the BOM purl/bom-ref (but we DO encode for HTTP URLs).
PURL_KEEP_AT_SYMBOL_FOR_SCOPES = False

# =========================


def now_utc_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json_file(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def http_get_json(url: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            data = resp.read()
        return json.loads(data.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise RuntimeError(f"HTTP {e.code} for {url}\n{body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error for {url}: {e}") from e


def npm_registry_package_url(pkg_name: str) -> str:
    # Registry expects scoped names encoded like @scope%2Fname
    encoded = quote(pkg_name, safe="")
    return f"{REGISTRY_BASE.rstrip('/')}/{encoded}"


def npm_registry_version_url(pkg_name: str, version: str) -> str:
    # Version endpoint: /<pkg>/<version>
    encoded_pkg = quote(pkg_name, safe="")
    encoded_ver = quote(version, safe="")
    return f"{REGISTRY_BASE.rstrip('/')}/{encoded_pkg}/{encoded_ver}"


def safe_url(u: Any) -> Optional[str]:
    if not u:
        return None
    if isinstance(u, dict):
        return None
    s = str(u).strip()
    if s.startswith("http://") or s.startswith("https://"):
        return s
    return None


def normalize_license(lic: Any) -> str:
    # npm "license" can be string or object
    if not lic:
        return ""
    if isinstance(lic, str):
        return lic.strip()
    if isinstance(lic, dict):
        t = lic.get("type")
        if isinstance(t, str) and t.strip():
            return t.strip()
    if isinstance(lic, list):
        for x in lic:
            s = normalize_license(x)
            if s:
                return s
    return ""


def extrefs_from_registry_version(ver_obj: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    externalReferences types must be in DT/CycloneDX enum:
    [vcs, issue-tracker, website, advisories, bom, mailing-list, social, chat,
     documentation, support, distribution, license, build-meta, build-system, other]
    We'll use: website, vcs, issue-tracker, distribution, documentation (if present).
    """
    out: List[Dict[str, str]] = []

    home = safe_url(ver_obj.get("homepage"))
    if home:
        out.append({"type": "website", "url": home})

    repo = ver_obj.get("repository")
    repo_url = None
    if isinstance(repo, str):
        repo_url = repo.strip()
    elif isinstance(repo, dict):
        repo_url = (repo.get("url") or "").strip()
    if repo_url:
        repo_url = repo_url.replace("git+", "")
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]
        if repo_url.startswith("http://") or repo_url.startswith("https://"):
            out.append({"type": "vcs", "url": repo_url})

    bugs = ver_obj.get("bugs")
    bugs_url = None
    if isinstance(bugs, str):
        bugs_url = bugs.strip()
    elif isinstance(bugs, dict):
        bugs_url = (bugs.get("url") or "").strip()
    if bugs_url and (bugs_url.startswith("http://") or bugs_url.startswith("https://")):
        out.append({"type": "issue-tracker", "url": bugs_url})

    dist = ver_obj.get("dist") or {}
    if isinstance(dist, dict):
        tarball = safe_url(dist.get("tarball"))
        if tarball:
            out.append({"type": "distribution", "url": tarball})

    docs = safe_url(ver_obj.get("documentation"))
    if docs:
        out.append({"type": "documentation", "url": docs})

    # de-dupe
    seen: Set[Tuple[str, str]] = set()
    dedup: List[Dict[str, str]] = []
    for r in out:
        key = (r.get("type", ""), r.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(r)
    return dedup


def parse_group_and_name(full_name: str) -> Tuple[Optional[str], str]:
    """
    Scoped packages: "@babel/core" -> ("babel", "core")
    Unscoped: "lodash" -> (None, "lodash")
    """
    full_name = (full_name or "").strip()
    if full_name.startswith("@") and "/" in full_name:
        scope, name = full_name[1:].split("/", 1)
        scope = scope.strip()
        name = name.strip()
        return (scope or None, name or full_name)
    return (None, full_name)


def npm_purl(full_name: str, version: str) -> str:
    """
    purl/bom-ref for components.
    User requirement: keep '@' for scoped packages in purl/bom-ref by default.
      - scoped: pkg:npm/@babel/core@7.15.5
      - unscoped: pkg:npm/lodash@4.17.21

    Note: The package-url spec often percent-encodes '@' as '%40'. If you ever need that,
    set PURL_KEEP_AT_SYMBOL_FOR_SCOPES=False and update this function accordingly.
    """
    full_name = (full_name or "").strip()
    version = (version or "").strip()
    if version:
        return f"pkg:npm/{full_name}@{version}"
    return f"pkg:npm/{full_name}"


def root_purl(name: str, version: str) -> str:
    # Root metadata component purl
    name = (name or "").strip()
    version = (version or "").strip()
    return npm_purl(name, version) if name else f"pkg:npm/{Config.project_group}-root@{version or '0.0.0'}"


# -------------------------
# SemVer utilities (minimal)
# -------------------------

@dataclass(frozen=True, order=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: Tuple[Any, ...] = ()

def parse_semver(v: str) -> Optional[SemVer]:
    """
    Parse versions like 1.2.3, 1.2.3-beta.1
    Returns None if not parseable.
    """
    v = (v or "").strip()
    if v.startswith("v"):
        v = v[1:]
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?(?:\+([0-9A-Za-z.\-]+))?$", v)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    pre = m.group(4) or ""
    prerelease: Tuple[Any, ...] = ()
    if pre:
        parts: List[Any] = []
        for p in pre.split("."):
            if p.isdigit():
                parts.append(int(p))
            else:
                parts.append(p)
        prerelease = tuple(parts)
    return SemVer(major, minor, patch, prerelease)

def semver_is_prerelease(sv: SemVer) -> bool:
    return len(sv.prerelease) > 0

def semver_cmp(a: SemVer, b: SemVer) -> int:
    # Compare core
    if (a.major, a.minor, a.patch) != (b.major, b.minor, b.patch):
        return -1 if (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch) else 1
    # Handle prerelease: prerelease < release
    if not a.prerelease and b.prerelease:
        return 1
    if a.prerelease and not b.prerelease:
        return -1
    if not a.prerelease and not b.prerelease:
        return 0
    # Both prerelease: compare identifiers
    for x, y in zip(a.prerelease, b.prerelease):
        if x == y:
            continue
        # ints < strings
        if isinstance(x, int) and isinstance(y, str):
            return -1
        if isinstance(x, str) and isinstance(y, int):
            return 1
        return -1 if x < y else 1
    # shorter prerelease wins
    if len(a.prerelease) == len(b.prerelease):
        return 0
    return -1 if len(a.prerelease) < len(b.prerelease) else 1

def semver_satisfies_simple(sv: SemVer, op: str, target: SemVer) -> bool:
    c = semver_cmp(sv, target)
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op in ("=", "=="):
        return c == 0
    return False

def expand_caret(base: SemVer) -> Tuple[str, SemVer, str, SemVer]:
    # ^1.2.3 := >=1.2.3 <2.0.0 ; ^0.2.3 := >=0.2.3 <0.3.0 ; ^0.0.3 := >=0.0.3 <0.0.4
    if base.major > 0:
        upper = SemVer(base.major + 1, 0, 0)
    elif base.minor > 0:
        upper = SemVer(0, base.minor + 1, 0)
    else:
        upper = SemVer(0, 0, base.patch + 1)
    return (">=", base, "<", upper)

def expand_tilde(base: SemVer) -> Tuple[str, SemVer, str, SemVer]:
    # ~1.2.3 := >=1.2.3 <1.3.0
    upper = SemVer(base.major, base.minor + 1, 0)
    return (">=", base, "<", upper)

def parse_wildcard(spec: str) -> Optional[Tuple[int, Optional[int]]]:
    # "1.x" or "1.*" -> (1, None) ; "1.2.x" -> (1, 2)
    m = re.match(r"^(\d+)\.(x|\*)$", spec)
    if m:
        return (int(m.group(1)), None)
    m2 = re.match(r"^(\d+)\.(\d+)\.(x|\*)$", spec)
    if m2:
        return (int(m2.group(1)), int(m2.group(2)))
    return None


def parse_semver_loose(v: str) -> Optional[SemVer]:
    """
    Accepts:
      1
      1.2
      1.2.3
      1.2.3-beta.1
    Missing minor/patch default to 0.
    """
    v = (v or "").strip()
    if v.startswith("v"):
        v = v[1:]

    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+([0-9A-Za-z.\-]+))?$", v)
    if not m:
        return None

    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)

    pre = m.group(4) or ""
    prerelease: Tuple[Any, ...] = ()
    if pre:
        parts: List[Any] = []
        for p in pre.split("."):
            parts.append(int(p) if p.isdigit() else p)
        prerelease = tuple(parts)

    return SemVer(major, minor, patch, prerelease)


def normalize_range_spec(spec: str) -> str:
    """
    Normalize npm-style shorthand ranges:
      "1"     -> "1.x"
      "1.2"   -> "1.2.x"
      "^1"    -> "^1.0.0"
      "^1.2"  -> "^1.2.0"
      "~1"    -> "~1.0.0"
      "~1.2"  -> "~1.2.0"
    """
    s = (spec or "").strip()
    if not s:
        return s

    # strip leading '=' commonly used in some manifests
    if s.startswith("="):
        s = s[1:].strip()

    # partial major / major.minor become X-ranges per npm semver
    if re.fullmatch(r"\d+", s):
        return f"{s}.x"
    if re.fullmatch(r"\d+\.\d+", s):
        return f"{s}.x"

    # caret/tilde with partials
    m = re.fullmatch(r"([\^~])\s*(\d+)$", s)
    if m:
        return f"{m.group(1)}{m.group(2)}.0.0"
    m = re.fullmatch(r"([\^~])\s*(\d+)\.(\d+)$", s)
    if m:
        return f"{m.group(1)}{m.group(2)}.{m.group(3)}.0"

    return s


def satisfies_range(sv: SemVer, spec: str) -> bool:
    """
    Minimal range support:
    - exact: 1.2.3
    - caret: ^1.2.3
    - tilde: ~1.2.3
    - wildcards: 1.x, 1.2.x, *
    - comparator sets: ">=1.2.3 <2.0.0"
    - hyphen: "1.2.3 - 2.3.4"
    - OR: ">=1 <2 || >=3"
    """
    spec = normalize_range_spec(spec)
    spec = (spec or "").strip()
    if not spec or spec == "*" or spec.lower() == "latest":
        return True

    # OR
    if "||" in spec:
        return any(satisfies_range(sv, part.strip()) for part in spec.split("||"))

    # Hyphen range
    mhy = re.match(r"^(\S+)\s*-\s*(\S+)$", spec)
    if mhy:
        # a = parse_semver(mhy.group(1))
        # b = parse_semver(mhy.group(2))
        a = parse_semver_loose(mhy.group(1))
        b = parse_semver_loose(mhy.group(2))
        if a and b:
            return semver_satisfies_simple(sv, ">=", a) and semver_satisfies_simple(sv, "<=", b)

    # Wildcards
    wc = parse_wildcard(spec)
    if wc:
        maj, minr = wc
        if sv.major != maj:
            return False
        if minr is None:
            return True
        return sv.minor == minr

    # caret / tilde
    if spec.startswith("^"):
        #base = parse_semver(spec[1:].strip())
        base = parse_semver_loose(spec[1:].strip())
        if not base:
            return False
        op1, t1, op2, t2 = expand_caret(base)
        return semver_satisfies_simple(sv, op1, t1) and semver_satisfies_simple(sv, op2, t2)

    if spec.startswith("~"):
        base = parse_semver(spec[1:].strip())
        if not base:
            return False
        op1, t1, op2, t2 = expand_tilde(base)
        return semver_satisfies_simple(sv, op1, t1) and semver_satisfies_simple(sv, op2, t2)

    # comparator set
    tokens = spec.split()
    if len(tokens) >= 2 and any(tok.startswith((">=", "<=", ">", "<", "=")) for tok in tokens):
        ok = True
        for tok in tokens:
            m = re.match(r"^(>=|<=|>|<|=|==)\s*(\S+)$", tok)
            if not m:
                continue
            op = m.group(1)
            #tv = parse_semver(m.group(2))
            tv = parse_semver_loose(m.group(2))
            if not tv:
                ok = False
                break
            if not semver_satisfies_simple(sv, op, tv):
                ok = False
                break
        return ok

    # exact
    ex = parse_semver(spec)
    if ex:
        return semver_satisfies_simple(sv, "==", ex)

    return False


# -------------------------
# Registry resolution logic
# -------------------------

class RegistryClient:
    def __init__(self) -> None:
        # cache full package docs: name -> doc
        self.pkg_cache: Dict[str, Dict[str, Any]] = {}
        # cache version docs: (name, version) -> doc
        self.ver_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def get_package_doc(self, name: str) -> Dict[str, Any]:
        if name in self.pkg_cache:
            return self.pkg_cache[name]
        doc = http_get_json(npm_registry_package_url(name))
        if not isinstance(doc, dict):
            raise RuntimeError(f"Unexpected registry response for {name}")
        self.pkg_cache[name] = doc
        return doc

    def get_version_doc(self, name: str, version: str) -> Dict[str, Any]:
        key = (name, version)
        if key in self.ver_cache:
            return self.ver_cache[key]
        doc = http_get_json(npm_registry_version_url(name, version))
        if not isinstance(doc, dict):
            raise RuntimeError(f"Unexpected registry response for {name}@{version}")
        self.ver_cache[key] = doc
        return doc

    def resolve_version(self, name: str, range_spec: str) -> Optional[str]:
        """
        Resolve a version range to a specific version.
        - If spec is exact and exists: return it
        - If spec is "*" or "latest": use dist-tags.latest
        - Otherwise: pick highest satisfying version (excluding prereleases unless spec includes prerelease)
        """
        raw_spec = (range_spec or "").strip()
        doc = self.get_package_doc(name)

        dist_tags = doc.get("dist-tags") or {}
        versions = doc.get("versions") or {}

        if not isinstance(versions, dict) or not versions:
            return None

        # exact version shortcut (raw, before normalization)
        if raw_spec in versions:
            return raw_spec

        # normalize shorthand range specs like "1" -> "1.x"
        range_spec = normalize_range_spec(raw_spec)

        # tags / latest logic (unchanged)
        if not range_spec or range_spec == "*" or range_spec.lower() == "latest":
            latest = dist_tags.get("latest")
            if isinstance(latest, str) and latest in versions:
                return latest
        if range_spec and range_spec in dist_tags and isinstance(dist_tags[range_spec], str):
            tv = dist_tags[range_spec]
            if tv in versions:
                return tv

        allow_prerelease = "-" in range_spec

        candidates: List[Tuple[SemVer, str]] = []
        for v in versions.keys():
            sv = parse_semver(v)
            if not sv:
                continue
            if semver_is_prerelease(sv) and not allow_prerelease:
                continue
            if satisfies_range(sv, range_spec):
                candidates.append((sv, v))

        if not candidates:
            # ✅ NEW: If the spec is shorthand like "1" / "1.2" (or normalized to "1.x"/"1.2.x")
            # and we still couldn't resolve it, fall back to latest.
            # This mimics "best effort" behavior when metadata is weird or incomplete.
            raw_is_shorthand = bool(re.fullmatch(r"\d+(\.\d+){0,2}", raw_spec))
            norm_is_shorthand = bool(re.fullmatch(r"\d+(\.\d+){0,2}\.x", range_spec))

            if raw_is_shorthand or norm_is_shorthand:
                latest = dist_tags.get("latest")
                if isinstance(latest, str) and latest in versions:
                    return latest

                # If "latest" tag isn't present, fall back to the highest parseable semver overall.
                best_sv: Optional[SemVer] = None
                best_v: Optional[str] = None
                for v in versions.keys():
                    sv = parse_semver(v)
                    if not sv:
                        continue
                    # keep same prerelease rule as above
                    if semver_is_prerelease(sv) and not allow_prerelease:
                        continue
                    if best_sv is None or semver_cmp(sv, best_sv) > 0:
                        best_sv, best_v = sv, v
                return best_v

            return None

        best_sv, best_v = candidates[0]
        for sv, v in candidates[1:]:
            if semver_cmp(sv, best_sv) > 0:
                best_sv, best_v = sv, v
        return best_v


def is_unresolvable_spec(spec: str) -> bool:
    s = (spec or "").strip().lower()
    return any(s.startswith(p) for p in ("file:", "git:", "github:", "http:", "https:", "workspace:", "link:"))


# -------------------------
# package-lock parsing
# -------------------------

def parse_lock_tree(lock_obj: Dict[str, Any], include_dev: bool) -> Dict[Tuple[str, str], Set[Tuple[str, str]]]:
    """
    Parse lock_obj["dependencies"] tree (works for lockfile v1/v2/v3) into adjacency:
      (name, version) -> set of (dep_name, dep_version)
    Uses nested installed dependency objects which contain exact versions.
    """
    deps_root = lock_obj.get("dependencies")
    if not isinstance(deps_root, dict):
        return {}

    adj: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}

    def walk(dep_name: str, dep_obj: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        if not isinstance(dep_obj, dict):
            return None

        # dev filtering
        if not include_dev and dep_obj.get("dev") is True:
            return None

        ver = dep_obj.get("version")
        if not isinstance(ver, str) or not ver.strip():
            return None
        ver = ver.strip()

        node = (dep_name, ver)
        adj.setdefault(node, set())

        children = dep_obj.get("dependencies")
        if isinstance(children, dict):
            for child_name, child_obj in children.items():
                child_node = walk(child_name, child_obj)
                if child_node:
                    adj[node].add(child_node)

        return node

    for top_name, top_obj in deps_root.items():
        walk(top_name, top_obj)

    return adj


# -------------------------
# SBOM generation
# -------------------------

def main() -> int:
    Config.package_json_file_path = Path(Config.sbom_input_dir, Config.package_json_file_name)
    Config.package_lock_json_file_path = Path(Config.sbom_input_dir, Config.package_lock_json_file_name)
    Config.npmrc_file_path = Path(Config.sbom_input_dir, Config.npmrc_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    if not Config.package_json_file_path.is_file():
        print(f"ERROR: package.json not found: {Config.package_json_file_path.resolve()}")
        return 2

    pkg = read_json_file(Config.package_json_file_path)

    # Determine metadata.component name/version
    project_name = (Config.project_name or (pkg.get("name") or "")).strip() or "npm-package-json"
    project_version = (Config.project_version or (pkg.get("version") or "")).strip() or "0.0.0"

    # Roots from package.json
    roots: Dict[str, str] = {}
    deps = pkg.get("dependencies") or {}
    if isinstance(deps, dict):
        roots.update({k: str(v) for k, v in deps.items()})
    if INCLUDE_DEV_DEPENDENCIES:
        dev = pkg.get("devDependencies") or {}
        if isinstance(dev, dict):
            # do not overwrite runtime deps
            for k, v in dev.items():
                roots.setdefault(k, str(v))

    if not roots:
        print("WARNING: No dependencies found in package.json (dependencies/devDependencies).")

    client = RegistryClient()

    # Build graph: node is (full_name, version)
    adjacency: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
    root_nodes: List[Tuple[str, str]] = []

    # If lockfile present, use it for exact graph
    used_lock = False
    if USE_PACKAGE_LOCK_IF_PRESENT and Config.package_lock_json_file_path.is_file():
        lock_obj = read_json_file(Config.package_lock_json_file_path)
        adjacency = parse_lock_tree(lock_obj, INCLUDE_DEV_DEPENDENCIES)
        used_lock = True

        # root_nodes from top-level lock dependencies (filtered to package.json roots if possible)
        # We'll resolve root_nodes by finding the installed versions for each root name in the lock's top dependencies.
        lock_deps = lock_obj.get("dependencies") if isinstance(lock_obj, dict) else None
        if isinstance(lock_deps, dict):
            for name in roots.keys():
                obj = lock_deps.get(name)
                if isinstance(obj, dict) and isinstance(obj.get("version"), str):
                    root_nodes.append((name, obj["version"].strip()))

    # Otherwise, resolve via registry (semver)
    if not used_lock:
        if PRINT_DEBUG:
            print("No usable package-lock.json detected; resolving ranges via registry (highest satisfying).")

        visited: Set[Tuple[str, str]] = set()
        stack: List[Tuple[str, str]] = []

        # resolve roots
        for name, spec in roots.items():
            if is_unresolvable_spec(spec):
                if PRINT_DEBUG:
                    print(f"Skipping unresolvable root spec (non-registry): {name} -> {spec}")
                continue
            ver = client.resolve_version(name, spec)
            if not ver:
                print(f"WARNING: Could not resolve version for {name} with spec '{spec}'")
                continue
            node = (name, ver)
            root_nodes.append(node)
            stack.append(node)

        # DFS/BFS resolve dependency graph from registry
        while stack:
            name, ver = stack.pop()
            if (name, ver) in visited:
                continue
            visited.add((name, ver))
            adjacency.setdefault((name, ver), set())

            ver_doc = client.get_version_doc(name, ver)
            dep_maps: List[Dict[str, Any]] = []
            if isinstance(ver_doc.get("dependencies"), dict):
                dep_maps.append(ver_doc["dependencies"])
            if isinstance(ver_doc.get("optionalDependencies"), dict):
                dep_maps.append(ver_doc["optionalDependencies"])

            combined: Dict[str, str] = {}
            for dm in dep_maps:
                for k, v in dm.items():
                    combined[k] = str(v)

            for dep_name, dep_spec in combined.items():
                if is_unresolvable_spec(dep_spec):
                    if PRINT_DEBUG:
                        print(f"Skipping unresolvable dep spec (non-registry): {name}@{ver} -> {dep_name} {dep_spec}")
                    continue

                dep_ver = client.resolve_version(dep_name, dep_spec)
                if not dep_ver:
                    if PRINT_DEBUG:
                        print(f"WARNING: Could not resolve {dep_name} spec '{dep_spec}' (required by {name}@{ver})")
                    continue

                dep_node = (dep_name, dep_ver)
                adjacency[(name, ver)].add(dep_node)
                if dep_node not in visited:
                    stack.append(dep_node)

    # Enrich all nodes from registry (description/license/extrefs)
    # Note: even in lockfile mode, we still query registry for metadata per (name, version).
    all_nodes: Set[Tuple[str, str]] = set(adjacency.keys())
    for depset in adjacency.values():
        all_nodes.update(depset)
    all_nodes.update(root_nodes)

    # Remove any accidental empty nodes
    all_nodes = {n for n in all_nodes if n[0] and n[1]}

    # Build components (dependencies only)
    components_by_ref: Dict[str, Dict[str, Any]] = {}

    for name, ver in sorted(all_nodes, key=lambda t: (t[0].lower(), t[1])):
        ver_doc = client.get_version_doc(name, ver)

        desc = (ver_doc.get("description") or "").strip()
        lic_name = normalize_license(ver_doc.get("license"))
        licenses = [{"license": {"name": lic_name}}] if lic_name else []
        extrefs = extrefs_from_registry_version(ver_doc)

        group, comp_name = parse_group_and_name(name)
        purl = npm_purl(name, ver)

        comp: Dict[str, Any] = {
            "type": "library",
            "name": comp_name,
            "version": ver,
            "purl": purl,
            "bom-ref": purl,
            "description": desc or "",
            "licenses": licenses,
            "externalReferences": extrefs,
        }
        # ✅ include group only for scoped packages
        if group:
            comp["group"] = group

        components_by_ref[purl] = comp

    # Build dependencies[] entries
    def ref_of(node: Tuple[str, str]) -> str:
        return npm_purl(node[0], node[1])

    deps_entries: List[Dict[str, Any]] = []

    # Root metadata component refs
    root_bom_ref = root_purl(project_name, project_version)

    # Root dependsOn = resolved root nodes (purls)
    root_refs = [ref_of(n) for n in root_nodes if n[0] and n[1]]
    # de-dupe stable
    seen_rr: Set[str] = set()
    root_refs = [r for r in root_refs if not (r in seen_rr or seen_rr.add(r))]

    deps_entries.append({"ref": root_bom_ref, "dependsOn": sorted(set(root_refs))})

    # Each component node entry
    # Ensure every node has an entry even if it has no deps
    for node in sorted(all_nodes, key=lambda t: (t[0].lower(), t[1])):
        ref = ref_of(node)
        child_refs = sorted({ref_of(d) for d in adjacency.get(node, set()) if d[0] and d[1]})
        deps_entries.append({"ref": ref, "dependsOn": child_refs})

    # Final BOM
    out: Dict[str, Any] = {}
    out["bomFormat"] = "CycloneDX"
    out["specVersion"] = SBOM_SPEC_VERSION
    out["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    out["version"] = 1
    out["metadata"] = {
        "timestamp": now_utc_iso_z(),
        "component": {
            "type": METADATA_COMPONENT_TYPE,
            "name": project_name,
            "group": Config.project_group,   # ✅ only hard-coded group
            "version": project_version,
            "bom-ref": root_bom_ref,
            "purl": root_bom_ref,
        },
    }
    out["components"] = [components_by_ref[k] for k in sorted(components_by_ref.keys())]
    out["dependencies"] = deps_entries

    Config.sbom_output_file_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if PRINT_DEBUG:
        mode = "package-lock.json" if used_lock else "registry range resolution"
        print(f"Mode: {mode}")
        print(f"Root deps: {len(root_nodes)}")
        print(f"Components: {len(components_by_ref)}")
        print(f"Dependencies entries: {len(deps_entries)}")
        print(f"Wrote: {Config.sbom_output_file_path.resolve()}")

    print(f"SBOM generated: {Config.sbom_output_file_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())