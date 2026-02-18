#!/usr/bin/env python3
"""
Generate a CycloneDX SBOM.json for npm packages listed in package.json.

Goals (mirrors the PyPI + Go generators):
- Hard-coded config at top (no CLI args)
- Dependency-Track accepted CycloneDX JSON format:
  {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:...",
    "version": 1,
    "metadata": { "timestamp": "...", "component": {...} },
    "components": [...],
    "dependencies": [...]
  }
- metadata.component is NOT duplicated into components[]
- bom-ref is the purl for packages (pkg:npm/<name>@<version>)
- components include best-effort enrichment:
  - description
  - licenses
  - externalReferences (homepage/repository/bugs)
- Only includes packages reachable from the dependency tree resolved by npm.

How it works:
1) Creates a TEMP working directory
2) Copies package.json (+ package-lock.json if present) into it
3) Runs `npm ci` (if lockfile exists) else `npm install` to create node_modules
4) Reads the dependency tree from `npm ls --all --json`
5) Reads package metadata from node_modules/<pkg>/package.json
6) Writes SBOM.json
7) Deletes the temp directory (including node_modules)

Prereqs:
- Node.js + npm installed and on PATH (npm must be available).
"""

from configuration import Configuration as Config
import json
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote


# Dependency-Track accepted CycloneDX version (same as your other generators)
SBOM_SPEC_VERSION = "1.5"

# metadata.component fields
METADATA_COMPONENT_TYPE = "library"
# Config.project_name = "npm-package-json"
# Config.project_version = "0.0.0"
# Config.project_group = ""  # keep for parity with PyPI/Go generators

# If True, include devDependencies in the npm tree.
INCLUDE_DEV_DEPENDENCIES = True

# Prefer deterministic install if lockfile exists.
USE_NPM_CI_IF_LOCKFILE = True

# If you're on an offline/closed network, set this False and ensure node_modules is already present
# in the temp dir approach won't help; best is to rely on an internal registry + lockfile.
ALLOW_NPM_INSTALL = True

# Optional: if you want to hard-code the executable name/path.
# Examples: "npm.cmd", "C:\\Program Files\\nodejs\\npm.cmd"
NPM_EXECUTABLE_OVERRIDE = ""

# Optional: require exact versions (or prefixes) for safety.
# Examples:
#   REQUIRED_NODE_VERSION_PREFIX = "v18."
#   REQUIRED_NPM_VERSION_PREFIX = "9."
REQUIRED_NODE_VERSION_PREFIX = ""
REQUIRED_NPM_VERSION_PREFIX = ""

PRINT_DEBUG = False

# =========================


def resolve_node_executable_from_npm(npm_exe: str) -> Optional[str]:
    """
    Try to find the Node executable that pairs with the selected npm.
    - Windows: npm.cmd usually lives next to node.exe
    - Linux/mac: npm often lives next to node
    Falls back to PATH if we can't find a sibling.
    """
    p = Path(npm_exe)
    if p.is_file():
        if os.name == "nt":
            candidate = p.with_name("node.exe")
            if candidate.is_file():
                return str(candidate)
        else:
            candidate = p.with_name("node")
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

    # Fallback: whatever "node" is on PATH
    found = shutil.which("node.exe" if os.name == "nt" else "node")
    return found


def ensure_node_npm_versions(npm_exe: str) -> None:
    """
    Validate node/npm versions if REQUIRED_* prefixes are set.
    """
    # npm version
    npm_v = run([npm_exe, "--version"]).stdout.strip()

    if REQUIRED_NPM_VERSION_PREFIX and not npm_v.startswith(REQUIRED_NPM_VERSION_PREFIX):
        raise RuntimeError(
            f"npm version check failed. Expected prefix '{REQUIRED_NPM_VERSION_PREFIX}', got '{npm_v}'. "
            f"Resolved npm: {npm_exe}"
        )

    node_exe = resolve_node_executable_from_npm(npm_exe)
    if not node_exe:
        raise RuntimeError("Could not resolve node executable (neither sibling nor PATH).")

    node_v = run([node_exe, "--version"]).stdout.strip()

    if REQUIRED_NODE_VERSION_PREFIX and not node_v.startswith(REQUIRED_NODE_VERSION_PREFIX):
        raise RuntimeError(
            f"node version check failed. Expected prefix '{REQUIRED_NODE_VERSION_PREFIX}', got '{node_v}'. "
            f"Resolved node: {node_exe} (from npm: {npm_exe})"
        )


def _rmtree_onerror(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    try:
        func(path)
    except Exception:
        pass


def run(cmd: List[str], *, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    cp = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            "Command failed.\n"
            f"Exit code: {cp.returncode}\n"
            f"Command: {' '.join(cmd)}\n"
            f"--- stdout ---\n{cp.stdout}\n"
            f"--- stderr ---\n{cp.stderr}\n"
        )
    return cp


def now_utc_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_npm_executable() -> str:
    override = (NPM_EXECUTABLE_OVERRIDE or "").strip()
    if override:
        p = Path(override)
        if p.is_file():
            return str(p)
        found = shutil.which(override)
        if found:
            return found
        raise RuntimeError(f"NPM_EXECUTABLE_OVERRIDE was set but not found: {override}")

    candidates = ["npm"]
    if os.name == "nt":
        candidates = ["npm.cmd", "npm.exe", "npm"]

    for c in candidates:
        found = shutil.which(c)
        if found:
            return found

    raise RuntimeError(
        "npm executable not found on PATH. Install Node.js/npm or set NPM_EXECUTABLE_OVERRIDE "
        r"(e.g. C:\Program Files\nodejs\npm.cmd)."
    )


NPM_EXE = resolve_npm_executable()


def ensure_npm_available() -> None:
    run([NPM_EXE, "--version"])


def parse_npm_group_and_name(full_name: str) -> Tuple[Optional[str], str]:
    """
    Scoped packages: "@scope/name" -> (scope, name)
      Example: "@babel/core" -> ("babel", "core")
    Unscoped packages: "lodash" -> (None, "lodash")
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
    Proper purl for npm:
      - unscoped: pkg:npm/lodash@4.17.21
      - scoped:   pkg:npm/%40babel/core@7.24.0    (encode '@' as %40)
    """
    full_name = (full_name or "").strip()
    version = (version or "").strip()

    if full_name.startswith("@") and "/" in full_name:
        scope, name = full_name.split("/", 1)          # scope includes leading '@'
        scope_enc = quote(scope, safe="")              # "@babel" -> "%40babel"
        path = f"{scope_enc}/{name.strip()}"
    else:
        path = full_name

    if version:
        return f"pkg:npm/{path}@{version}"
    return f"pkg:npm/{path}"


def normalize_license(lic: Any) -> str:
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


def safe_url(u: Any) -> Optional[str]:
    if not u:
        return None
    if isinstance(u, dict):
        return None
    s = str(u).strip()
    if s.startswith("http://") or s.startswith("https://"):
        return s
    return None


def extrefs_from_package_meta(meta: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []

    home = safe_url(meta.get("homepage"))
    if home:
        out.append({"type": "website", "url": home})

    repo = meta.get("repository")
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

    bugs = meta.get("bugs")
    bugs_url = None
    if isinstance(bugs, str):
        bugs_url = bugs.strip()
    elif isinstance(bugs, dict):
        bugs_url = (bugs.get("url") or "").strip()
    if bugs_url and (bugs_url.startswith("http://") or bugs_url.startswith("https://")):
        out.append({"type": "issue-tracker", "url": bugs_url})

    docs = safe_url(meta.get("documentation"))
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


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def copy_if_exists(src: Path, dst_dir: Path) -> None:
    if src.is_file():
        shutil.copy2(src, dst_dir / src.name)


def npm_install(work_dir: Path) -> None:
    if not ALLOW_NPM_INSTALL:
        return

    has_lock = (work_dir / "package-lock.json").is_file()
    if USE_NPM_CI_IF_LOCKFILE and has_lock:
        cmd = [NPM_EXE, "ci"]
    else:
        cmd = [NPM_EXE, "install"]

    if not INCLUDE_DEV_DEPENDENCIES:
        cmd += ["--omit=dev"]

    run(cmd, cwd=work_dir)


def npm_ls_tree(work_dir: Path) -> Dict[str, Any]:
    cmd = [NPM_EXE, "ls", "--all", "--json"]
    if not INCLUDE_DEV_DEPENDENCIES:
        cmd += ["--omit=dev"]
    cp = run(cmd, cwd=work_dir)
    return json.loads(cp.stdout or "{}")


def node_modules_pkg_json(work_dir: Path, package_full_name: str) -> Optional[Path]:
    nm = work_dir / "node_modules"
    if not nm.is_dir():
        return None

    if package_full_name.startswith("@"):
        parts = package_full_name.split("/", 1)
        if len(parts) != 2:
            return None
        scope, name = parts
        p = nm / scope / name / "package.json"
    else:
        p = nm / package_full_name / "package.json"
    return p if p.is_file() else None


def traverse_npm_tree(
    node: Dict[str, Any],
    *,
    work_dir: Path,
    components_by_ref: Dict[str, Dict[str, Any]],
    edges_by_ref: Dict[str, Set[str]],
    visited: Set[str],
    is_root: bool = False,
    node_name_hint: str = "",
) -> str:
    # npm ls children often don't have "name"; the dict key is the name.
    full_name = (node.get("name") or node_name_hint or "").strip()
    version = (node.get("version") or "").strip()

    ref = "ROOT_PROJECT" if is_root else npm_purl(full_name, version)

    if ref not in visited:
        visited.add(ref)
        edges_by_ref.setdefault(ref, set())

        # ✅ Only dependencies become components
        if not is_root:
            if full_name and version:
                meta: Dict[str, Any] = {}
                pj = node_modules_pkg_json(work_dir, full_name)
                if pj:
                    try:
                        meta = read_json(pj)
                    except Exception:
                        meta = {}

                description = (meta.get("description") or node.get("description") or "").strip()
                lic = normalize_license(meta.get("license") or node.get("license"))
                licenses = [{"license": {"name": lic}}] if lic else []
                extrefs = extrefs_from_package_meta(meta)

                group, name = parse_npm_group_and_name(full_name)
                purl = npm_purl(full_name, version)

                comp: Dict[str, Any] = {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "bom-ref": purl,
                    "description": description or "",
                    "licenses": licenses,
                    "externalReferences": extrefs,
                }
                # ✅ Only include group for scoped packages
                if group:
                    comp["group"] = group

                components_by_ref[purl] = comp

    deps = node.get("dependencies") or {}
    if isinstance(deps, dict):
        for dep_key, child in deps.items():
            if not isinstance(child, dict):
                continue

            child_full_name = (child.get("name") or dep_key or "").strip()
            child_ver = (child.get("version") or "").strip()

            # skip unresolved entries
            if not child_full_name or not child_ver:
                continue

            child_ref = npm_purl(child_full_name, child_ver)
            edges_by_ref.setdefault(ref, set()).add(child_ref)

            traverse_npm_tree(
                child,
                work_dir=work_dir,
                components_by_ref=components_by_ref,
                edges_by_ref=edges_by_ref,
                visited=visited,
                is_root=False,
                node_name_hint=child_full_name,
            )

    return ref


def main() -> int:
    Config.package_json_file_path = Path(Config.sbom_input_dir, Config.package_json_file_name)
    Config.package_lock_json_file_path = Path(Config.sbom_input_dir, Config.package_lock_json_file_name)
    Config.npmrc_file_path = Path(Config.sbom_input_dir, Config.npmrc_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    if not Config.package_json_file_path.is_file():
        print(f"ERROR: package.json not found: {Config.package_json_file_path}")
        return 2

    try:
        #ensure_npm_available()
        run([NPM_EXE, "--version"])
        ensure_node_npm_versions(NPM_EXE)  # optional validation
    except Exception as e:
        #print(f"ERROR: npm not available (need Node.js + npm on PATH). Details:\n{e}")
        print(f"ERROR: npm/node not available or version mismatch. Details:\n{e}")
        return 2

    work_dir = Path(tempfile.mkdtemp(prefix="sbom_npm_"))
    try:
        # Copy inputs into temp dir
        copy_if_exists(Config.package_json_file_path, work_dir)
        copy_if_exists(Config.package_lock_json_file_path, work_dir)
        copy_if_exists(Config.npmrc_file_path, work_dir)

        # Install dependencies in isolated temp dir
        npm_install(work_dir)

        # Read resolved dependency tree
        tree = npm_ls_tree(work_dir)

        # Determine "roots" from the package.json dependencies keys
        pkg = read_json(work_dir / "package.json")
        dep_keys = list((pkg.get("dependencies") or {}).keys())
        dev_keys = list((pkg.get("devDependencies") or {}).keys())
        roots = dep_keys + (dev_keys if INCLUDE_DEV_DEPENDENCIES else [])
        # de-dupe preserve order
        seen: Set[str] = set()
        roots = [r for r in roots if not (r in seen or seen.add(r))]

        # Traverse tree -> components + edges
        components_by_ref: Dict[str, Dict[str, Any]] = {}
        edges_by_ref: Dict[str, Set[str]] = {}
        visited: Set[str] = set()

        traverse_npm_tree(
            tree,
            work_dir=work_dir,
            components_by_ref=components_by_ref,
            edges_by_ref=edges_by_ref,
            visited=visited,
            is_root=True,
        )

        # Build root_refs by resolving each root dependency to an installed version (if found in node_modules)
        root_refs: List[str] = []
        for r in roots:
            pj = node_modules_pkg_json(work_dir, r)
            if not pj:
                continue
            try:
                meta = read_json(pj)
            except Exception:
                continue
            name = (meta.get("name") or r).strip()
            ver = (meta.get("version") or "").strip()
            if name and ver:
                root_refs.append(npm_purl(name, ver))

        # de-dupe
        seen_rr: Set[str] = set()
        root_refs = [x for x in root_refs if not (x in seen_rr or seen_rr.add(x))]

        # metadata.component (not in components list)
        root_purl = npm_purl(Config.project_name, Config.project_version)
        root_bom_ref = root_purl

        # Build dependencies array (CycloneDX style)
        dependencies: List[Dict[str, Any]] = []
        dependencies.append({"ref": root_bom_ref, "dependsOn": sorted(set(root_refs))})

        # ROOT_PROJECT node edges -> hook to root as well (optional but helps when roots empty)
        if "ROOT_PROJECT" in edges_by_ref:
            depends = sorted({x for x in edges_by_ref.get("ROOT_PROJECT", set()) if x != "ROOT_PROJECT"})
            # If we didn't resolve root_refs, use this fallback
            if not root_refs and depends:
                dependencies[0]["dependsOn"] = depends

        # Add dependencies for each actual package ref we included
        for ref in sorted(components_by_ref.keys()):
            deps = sorted({d for d in edges_by_ref.get(ref, set()) if d in components_by_ref})
            dependencies.append({"ref": ref, "dependsOn": deps})

        # Components list (exclude metadata.component by design)
        components = [components_by_ref[k] for k in sorted(components_by_ref.keys())]

        # Final BOM object
        out: Dict[str, Any] = {}
        out["bomFormat"] = "CycloneDX"
        out["specVersion"] = SBOM_SPEC_VERSION
        out["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
        out["version"] = 1
        out["metadata"] = {
            "timestamp": now_utc_iso_z(),
            "component": {
                "type": METADATA_COMPONENT_TYPE,
                "name": Config.project_name,
                "group": Config.project_group,
                "version": Config.project_version,
                "bom-ref": root_bom_ref,
                "purl": root_purl,
            },
        }
        out["components"] = components
        out["dependencies"] = dependencies

        Config.sbom_output_file_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        if PRINT_DEBUG:
            print(f"Resolved npm executable: {NPM_EXE}")
            print(f"Roots (from package.json keys): {roots}")
            print(f"Root refs (resolved): {root_refs[:20]}{'...' if len(root_refs) > 20 else ''}")
            print(f"Components: {len(components)}")
            print(f"Dependencies entries: {len(dependencies)}")

        print(f"SBOM generated: {Config.sbom_output_file_path.resolve()}")
        return 0

    finally:
        shutil.rmtree(work_dir, ignore_errors=False, onerror=_rmtree_onerror)


if __name__ == "__main__":
    raise SystemExit(main())