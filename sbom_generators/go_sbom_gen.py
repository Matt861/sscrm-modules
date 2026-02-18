#!/usr/bin/env python3
"""
Generate a CycloneDX SBOM.json for Go modules listed in go.mod.

- Uses the Go toolchain to resolve the full module graph.
- Builds an SBOM from ONLY modules reachable in the module graph.
- Enriches component metadata (best-effort, offline):
  - description: first meaningful line from README (if present)
  - licenses: best-effort detection from LICENSE/COPYING files
  - externalReferences: pkg.go.dev + VCS/issue tracker for common hosts
- metadata.component includes: type, name, group, version, bom-ref, purl
- IMPORTANT: metadata.component is NOT duplicated into components[]

Also mirrors the PyPI script pattern by using an isolated temp Go cache that is deleted.
"""

from configuration import Configuration as Config
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# =========================
# Hard-coded configuration
# =========================

# PROJECT_DIR = Path(".").resolve()
# GO_MOD_FILE = PROJECT_DIR / "go.mod"
# OUTPUT_SBOM_FILE = PROJECT_DIR / "SBOM.json"
PROJECT_DIR_OVERRIDE: str = ""

# Dependency-Track friendly CycloneDX (match your PyPI generator default)
SBOM_SPEC_VERSION = "1.5"

# Root (metadata.component) fields
METADATA_COMPONENT_TYPE = "library"
METADATA_COMPONENT_GROUP = ""   # mirrors PyPI generator "pypi"
METADATA_COMPONENT_VERSION = "0.0.0"  # like PyPI generator default

PRINT_DEBUG = False

# If you are on a locked-down network, you may want to disable downloads and rely on existing cache.
# NOTE: If False, missing modules may lead to empty license/description data.
ALLOW_GO_DOWNLOADS = True

# =========================


@dataclass(frozen=True)
class ModID:
    path: str
    version: str  # may be ""

    def key(self) -> Tuple[str, str]:
        return (self.path, self.version)


def find_go_mod_dir(start: Path) -> Path:
    """
    Walk up from `start` to find a directory containing go.mod.
    """
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent

    for d in [cur, *cur.parents]:
        if (d / "go.mod").is_file():
            return d
    raise FileNotFoundError(f"Could not find go.mod by walking up from: {start.resolve()}")

def resolve_project_dir() -> Path:
    if PROJECT_DIR_OVERRIDE.strip():
        d = Path(PROJECT_DIR_OVERRIDE).expanduser().resolve()
        if not (d / "go.mod").is_file():
            raise FileNotFoundError(f"PROJECT_DIR_OVERRIDE does not contain go.mod: {d}")
        return d

    # Prefer the directory where this script lives (works well for PyCharm runs)
    here = Path(__file__).resolve()
    return find_go_mod_dir(here)


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


def ensure_go_available() -> None:
    run(["go", "version"])


def split_mod_token(token: str) -> ModID:
    token = token.strip()
    if not token:
        return ModID("", "")
    if "@" in token:
        p, v = token.rsplit("@", 1)
        return ModID(p, v)
    return ModID(token, "")


def go_purl(path: str, version: str) -> str:
    # purl "golang" expects module path; version is optional
    # Keep it simple and stable: pkg:golang/<module>@<version>
    if version:
        return f"pkg:golang/{path}@{version}"
    return f"pkg:golang/{path}"


def normalize_module_name_for_metadata(path: str) -> str:
    # Keep module path as name; Go modules don’t have a separate display-name concept
    return path.strip()


def safe_url(u: str) -> Optional[str]:
    if not u:
        return None
    u = u.strip()
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return None


def guess_external_references(mod_path: str) -> List[Dict[str, str]]:
    """
    Best-effort external references that are generally stable/offline.
    Keep types conservative and broadly accepted: website, vcs, issue-tracker, documentation.
    """
    refs: List[Dict[str, str]] = []

    # Documentation: pkg.go.dev works for most public modules
    doc_url = f"https://pkg.go.dev/{mod_path}"
    refs.append({"type": "documentation", "url": doc_url})

    # VCS + issues for common hosts
    if mod_path.startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
        base = f"https://{mod_path}"
        refs.append({"type": "vcs", "url": base})
        refs.append({"type": "issue-tracker", "url": base.rstrip("/") + "/issues"})
        refs.append({"type": "website", "url": base})

    # golang.org/x/... has docs; website is often the docs
    if mod_path.startswith("golang.org/"):
        refs.append({"type": "website", "url": doc_url})

    # De-dupe by (type,url)
    seen: Set[Tuple[str, str]] = set()
    out: List[Dict[str, str]] = []
    for r in refs:
        key = (r.get("type", ""), r.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


LICENSE_FILENAMES = [
    "LICENSE", "LICENSE.txt", "LICENSE.md",
    "COPYING", "COPYING.txt", "COPYING.md",
    "NOTICE", "NOTICE.txt", "NOTICE.md",
    "UNLICENSE", "UNLICENSE.txt",
]


def read_text_file_first_bytes(path: Path, max_bytes: int = 200_000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    return data[:max_bytes].decode("utf-8", errors="replace")


def detect_license_name(module_dir: Path) -> str:
    """
    Best-effort license detection from typical license files.
    Returns a human-readable license name or empty string.
    """
    if not module_dir or not module_dir.is_dir():
        return ""

    lic_text = ""
    lic_path = None
    for name in LICENSE_FILENAMES:
        p = module_dir / name
        if p.is_file():
            lic_path = p
            lic_text = read_text_file_first_bytes(p)
            break

    if not lic_text:
        return ""

    t = lic_text.lower()

    # Simple heuristics (good enough for metadata "license.name")
    if "apache license" in t and "version 2" in t:
        return "Apache-2.0"
    if "mit license" in t or ("permission is hereby granted" in t and "without restriction" in t):
        return "MIT"
    if "bsd license" in t and "redistribution and use" in t:
        # hard to distinguish 2/3-clause reliably; give generic
        return "BSD"
    if "mozilla public license" in t and "2.0" in t:
        return "MPL-2.0"
    if "gnu general public license" in t and "version 3" in t:
        return "GPL-3.0"
    if "gnu general public license" in t and "version 2" in t:
        return "GPL-2.0"
    if "gnu lesser general public license" in t and "version 3" in t:
        return "LGPL-3.0"
    if "gnu lesser general public license" in t and "version 2.1" in t:
        return "LGPL-2.1"
    if "isc license" in t:
        return "ISC"
    if "the unlicense" in t:
        return "Unlicense"

    # Fallback: if file exists but unknown text, return filename (still better than empty sometimes)
    return lic_path.name if lic_path else ""


README_FILENAMES = [
    "README", "README.txt", "README.md", "README.rst",
]


def extract_description_from_readme(module_dir: Path) -> str:
    """
    Best-effort description from README: first non-empty line, stripping markdown headings.
    """
    if not module_dir or not module_dir.is_dir():
        return ""

    readme_text = ""
    for name in README_FILENAMES:
        p = module_dir / name
        if p.is_file():
            readme_text = read_text_file_first_bytes(p, max_bytes=80_000)
            break

    if not readme_text:
        return ""

    for line in readme_text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Strip leading markdown heading markers
        s = re.sub(r"^#+\s*", "", s).strip()
        # Skip badge-only lines
        if s.startswith("![") and "](" in s:
            continue
        # Keep it short-ish
        return s[:300]
    return ""


def decode_multi_json(stream: str) -> List[Dict[str, Any]]:
    """
    Go commands like `go list -m -json all` emit multiple JSON objects concatenated.
    This decodes them safely.
    """
    objs: List[Dict[str, Any]] = []
    s = stream.strip()
    if not s:
        return objs

    dec = json.JSONDecoder()
    idx = 0
    while idx < len(s):
        # Skip whitespace
        while idx < len(s) and s[idx].isspace():
            idx += 1
        if idx >= len(s):
            break
        obj, next_idx = dec.raw_decode(s, idx)
        if isinstance(obj, dict):
            objs.append(obj)
        idx = next_idx
    return objs


def create_isolated_go_env(work_dir: Path) -> Dict[str, str]:
    """
    Create an isolated env so module downloads/caches don't pollute the user's global cache.
    Deleted at the end like the PyPI temp venv.
    """
    env = os.environ.copy()

    gopath = work_dir / "gopath"
    gomodcache = work_dir / "gomodcache"
    gocache = work_dir / "gocache"

    gopath.mkdir(parents=True, exist_ok=True)
    gomodcache.mkdir(parents=True, exist_ok=True)
    gocache.mkdir(parents=True, exist_ok=True)

    env["GOPATH"] = str(gopath)
    env["GOMODCACHE"] = str(gomodcache)
    env["GOCACHE"] = str(gocache)

    # Make output deterministic-ish
    env["GONOSUMDB"] = env.get("GONOSUMDB", "")
    env["GOPRIVATE"] = env.get("GOPRIVATE", "")

    return env


def go_mod_edit_json(cwd: Path, env: Dict[str, str]) -> Dict[str, Any]:
    cp = run(["go", "mod", "edit", "-json"], cwd=cwd, env=env)
    return json.loads(cp.stdout)


def go_list_modules_all(cwd: Path, env: Dict[str, str]) -> List[Dict[str, Any]]:
    cp = run(["go", "list", "-m", "-json", "all"], cwd=cwd, env=env)
    return decode_multi_json(cp.stdout)


def go_mod_graph(cwd: Path, env: Dict[str, str]) -> List[Tuple[ModID, ModID]]:
    cp = run(["go", "mod", "graph"], cwd=cwd, env=env)
    edges: List[Tuple[ModID, ModID]] = []
    for line in cp.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        a = split_mod_token(parts[0])
        b = split_mod_token(parts[1])
        if a.path and b.path:
            edges.append((a, b))
    return edges


def go_mod_download_all(cwd: Path, env: Dict[str, str]) -> None:
    # Best-effort download to populate Dir paths for license/README scanning.
    # This may hit the network; controlled by ALLOW_GO_DOWNLOADS.
    if not ALLOW_GO_DOWNLOADS:
        return
    run(["go", "mod", "download", "-json", "all"], cwd=cwd, env=env)


def module_effective_dir(mod_obj: Dict[str, Any]) -> Optional[Path]:
    """
    Prefer Replace.Dir when present (local replace), else Dir.
    """
    rep = mod_obj.get("Replace")
    if isinstance(rep, dict):
        d = rep.get("Dir")
        if d:
            return Path(d)
    d = mod_obj.get("Dir")
    if d:
        return Path(d)
    return None


def module_id_from_obj(mod_obj: Dict[str, Any]) -> ModID:
    return ModID(mod_obj.get("Path", ""), mod_obj.get("Version", "") or "")


def main() -> int:
    Config.go_mod_file_path = Path(Config.sbom_input_dir, Config.go_sbom_input_file)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")
    go_download_dir = Path(Config.root_dir, "downloads/go")

    if not Config.go_mod_file_path.is_file():
        print(f"ERROR: go.mod not found at: {Config.go_mod_file_path}")
        return 2

    try:
        ensure_go_available()
    except Exception as e:
        print(f"ERROR: Go toolchain not available (need 'go' on PATH). Details:\n{e}")
        return 2

    work_dir = Path(tempfile.mkdtemp(prefix="sbom_go_"))
    try:
        env = create_isolated_go_env(work_dir)

        # Read go.mod structure robustly
        mod_json = go_mod_edit_json(Config.sbom_input_dir, env)
        main_mod_path = (mod_json.get("Module") or {}).get("Path") or "go-module"
        metadata_name = main_mod_path  # closest analogue to "pypi-requirements"

        # Download modules so license/README scanning works (best-effort)
        go_mod_download_all(Config.sbom_input_dir, env)

        # Resolved module list (main + deps)
        all_mods = go_list_modules_all(Config.sbom_input_dir, env)

        # Identify main module object
        main_obj = next((m for m in all_mods if m.get("Main") is True), None)
        main_id = module_id_from_obj(main_obj) if main_obj else ModID(main_mod_path, "")

        # Direct requirements from go.mod (these mirror requirements.txt "roots")
        requires = mod_json.get("Require") or []
        require_ids_from_mod: List[ModID] = []
        for r in requires:
            p = r.get("Path")
            v = r.get("Version") or ""
            if p:
                require_ids_from_mod.append(ModID(p, v))

        # Map resolved modules by path to their resolved object (path is unique in list -m all)
        resolved_by_path: Dict[str, Dict[str, Any]] = {}
        for m in all_mods:
            p = m.get("Path")
            if p:
                resolved_by_path[p] = m

        # Build root_refs using resolved versions where possible
        root_refs: List[str] = []
        for rid in require_ids_from_mod:
            obj = resolved_by_path.get(rid.path)
            ver = (obj.get("Version") if obj else rid.version) or ""
            root_refs.append(go_purl(rid.path, ver))
        # de-dupe preserve order
        seen_rr: Set[str] = set()
        root_refs = [x for x in root_refs if not (x in seen_rr or seen_rr.add(x))]

        # Full module graph edges
        edges = go_mod_graph(Config.sbom_input_dir, env)

        # Build a set of dependency modules we will include as components (exclude main module)
        dep_mod_objs: List[Dict[str, Any]] = [m for m in all_mods if m.get("Main") is not True]
        dep_ids: Set[Tuple[str, str]] = set()
        for m in dep_mod_objs:
            mid = module_id_from_obj(m)
            if mid.path:
                dep_ids.add(mid.key())

        # Map ModID -> purl for included dependency modules
        id_to_purl: Dict[Tuple[str, str], str] = {}
        for m in dep_mod_objs:
            mid = module_id_from_obj(m)
            if mid.path:
                id_to_purl[mid.key()] = go_purl(mid.path, mid.version)

        # Build adjacency among included dependency modules only
        adjacency: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {k: set() for k in dep_ids}
        for a, b in edges:
            # skip edges from main module
            if a.path == main_id.path and (a.version == main_id.version or not a.version):
                continue
            if a.key() in adjacency and b.key() in dep_ids:
                adjacency[a.key()].add(b.key())

        # Ensure every module appears in dependencies even if it has no outgoing edges
        # (like PyPI generator)
        dependencies_list: List[Dict[str, Any]] = []
        for k in sorted(dep_ids, key=lambda t: (t[0].lower(), t[1])):
            ref = id_to_purl.get(k) or go_purl(k[0], k[1])
            deps = sorted({id_to_purl.get(d) or go_purl(d[0], d[1]) for d in adjacency.get(k, set())})
            dependencies_list.append({"ref": ref, "dependsOn": deps})

        # Build components with enriched metadata (best-effort from module directory)
        components: List[Dict[str, Any]] = []
        for m in sorted(dep_mod_objs, key=lambda x: ((x.get("Path") or "").lower(), x.get("Version") or "")):
            mid = module_id_from_obj(m)
            if not mid.path:
                continue

            purl = go_purl(mid.path, mid.version)
            bom_ref = purl

            mod_dir = module_effective_dir(m)
            description = extract_description_from_readme(mod_dir) if mod_dir else ""
            lic = detect_license_name(mod_dir) if mod_dir else ""
            licenses = [{"license": {"name": lic}}] if lic else []
            extrefs = guess_external_references(mid.path)

            components.append({
                "type": "library",
                "group": METADATA_COMPONENT_GROUP,
                "name": normalize_module_name_for_metadata(mid.path),
                "version": mid.version,
                "purl": purl,
                "bom-ref": bom_ref,
                "description": description or "",
                "licenses": licenses,
                "externalReferences": extrefs,
            })

        # metadata.component (not duplicated into components[])
        root_purl = go_purl(metadata_name, METADATA_COMPONENT_VERSION)
        root_bom_ref = root_purl

        # Root dependency node anchors to direct requires (like requirements.txt roots)
        dependencies_list.insert(0, {"ref": root_bom_ref, "dependsOn": sorted(set(root_refs))})

        # Final BOM object in the same layout/order as your PyPI generator
        out: Dict[str, Any] = {}
        out["bomFormat"] = "CycloneDX"
        out["specVersion"] = SBOM_SPEC_VERSION
        out["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
        out["version"] = 1
        out["metadata"] = {
            "timestamp": now_utc_iso_z(),
            "component": {
                "type": METADATA_COMPONENT_TYPE,
                "name": metadata_name,
                "group": METADATA_COMPONENT_GROUP,
                "version": METADATA_COMPONENT_VERSION,
                "bom-ref": root_bom_ref,
                "purl": root_purl,
            },
        }
        out["components"] = components
        out["dependencies"] = dependencies_list

        Config.sbom_output_file_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        if PRINT_DEBUG:
            print(f"Main module: {main_id.path} {main_id.version}")
            print(f"Direct requires (roots): {len(root_refs)}")
            print(f"Components: {len(components)}")
            print(f"Dependencies entries: {len(dependencies_list)}")

        print(f"SBOM generated: {Config.sbom_output_file_path}")
        return 0

    finally:
        shutil.rmtree(work_dir, ignore_errors=False, onerror=_rmtree_onerror)


if __name__ == "__main__":
    raise SystemExit(main())