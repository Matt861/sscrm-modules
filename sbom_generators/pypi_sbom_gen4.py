from configuration import Configuration as Config
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Dependency-Track 4.11.0 friendly CycloneDX
SBOM_SPEC_VERSION = "1.3"

# Root (metadata.component) fields
METADATA_COMPONENT_TYPE = "library"
METADATA_COMPONENT_GROUP = "pypi"
METADATA_COMPONENT_NAME = "pypi-requirements"
METADATA_COMPONENT_VERSION = "1.0.0"

# Optional: extra pip args (Nexus/proxy/etc.)
# PIP_EXTRA_ARGS = ["--index-url", "https://your.nexus/repository/pypi/simple", "--trusted-host", "your.nexus"]
PIP_EXTRA_ARGS: List[str] = []

PYTHON_EXECUTABLE = sys.executable

PRINT_DEBUG = False
# =========================


def _rmtree_onerror(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    try:
        func(path)
    except Exception:
        pass


def run(cmd: List[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    cp = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
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


def venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def now_utc_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def pep503_normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def parse_req_name_from_line(line: str) -> Optional[str]:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("-") and not raw.startswith("-r") and not raw.startswith("--requirement"):
        return None
    if "://" not in raw and "#" in raw:
        raw = raw.split("#", 1)[0].strip()
        if not raw:
            return None
    if "#egg=" in raw:
        egg = raw.split("#egg=", 1)[1].strip()
        return pep503_normalize(egg) if egg else None
    if " @ " in raw:
        left = raw.split("@", 1)[0].strip()
        m = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", left)
        return pep503_normalize(m.group(0)) if m else None
    m = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", raw)
    return pep503_normalize(m.group(0)) if m else None


def read_requirement_roots(req_file: Path) -> List[str]:
    roots: List[str] = []
    seen_files: Set[Path] = set()

    def _read(path: Path):
        p = path.resolve()
        if p in seen_files:
            return
        seen_files.add(p)
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("-r ") or s.startswith("--requirement "):
                parts = s.split(maxsplit=1)
                if len(parts) == 2:
                    child = (p.parent / parts[1].strip()).resolve()
                    if child.is_file():
                        _read(child)
                continue
            if s.startswith("-c ") or s.startswith("--constraint "):
                continue
            name = parse_req_name_from_line(s)
            if name:
                roots.append(name)

    _read(req_file)

    out: List[str] = []
    seen: Set[str] = set()
    for r in roots:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def compute_purl(dist_name_norm: str, version: str) -> str:
    return f"pkg:pypi/{dist_name_norm}@{version}"


def build_sbom_parts_inside_venv(py: Path, requirements_path: Path) -> Dict[str, Any]:
    """
    Runs a helper inside the venv so importlib.metadata reflects the venv.
    It returns only packages reachable from requirements roots, and enriches each component with:
    description/licenses/externalReferences derived from package metadata.
    """
    helper_code = r"""
import json, re, sys
from importlib import metadata

def pep503_normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())

def parse_name_from_req_string(req: str):
    if not req:
        return None
    req = req.strip()
    m = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", req)
    return pep503_normalize(m.group(0)) if m else None

def compute_purl(name_norm: str, version: str) -> str:
    return f"pkg:pypi/{name_norm}@{version}"

def safe_url(u: str):
    if not u:
        return None
    u = u.strip()
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return None

def extref_type(label: str, url: str):
    l = (label or "").strip().lower()
    u = (url or "").lower()
    if any(k in l for k in ["source", "repo", "repository", "code", "scm", "vcs"]):
        return "vcs"
    if any(k in l for k in ["bug", "issue", "tracker"]):
        return "issue-tracker"
    if any(k in l for k in ["doc", "docs", "documentation"]):
        return "documentation"
    if any(k in l for k in ["changelog", "release", "releases", "notes"]):
        return "release-notes"
    if "github.com" in u or u.endswith(".git"):
        return "vcs"
    return "website"

def parse_project_urls(msg):
    out = []
    vals = msg.get_all("Project-URL") or []
    for v in vals:
        if "," in v:
            label, url = v.split(",", 1)
            out.append((label.strip(), url.strip()))
        else:
            out.append(("Project-URL", v.strip()))
    return out

def pick_license_name(msg):
    lic = (msg.get("License") or "").strip()
    if lic and lic.lower() not in {"unknown", "n/a", "none"} and len(lic) <= 200:
        return lic
    classifiers = msg.get_all("Classifier") or []
    for c in classifiers:
        if c.startswith("License ::"):
            parts = [p.strip() for p in c.split("::")]
            if parts:
                return parts[-1]
    return ""

def read_roots(req_path):
    from pathlib import Path
    roots=[]
    seen=set()
    def parse_req_name_from_line(line: str):
        raw=line.strip()
        if not raw or raw.startswith("#"):
            return None
        if raw.startswith("-") and not raw.startswith("-r") and not raw.startswith("--requirement"):
            return None
        if "://" not in raw and "#" in raw:
            raw = raw.split("#", 1)[0].strip()
            if not raw:
                return None
        if "#egg=" in raw:
            egg = raw.split("#egg=", 1)[1].strip()
            return pep503_normalize(egg) if egg else None
        if " @ " in raw:
            left = raw.split("@", 1)[0].strip()
            m = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", left)
            return pep503_normalize(m.group(0)) if m else None
        m = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", raw)
        return pep503_normalize(m.group(0)) if m else None

    def _read(path: Path):
        path = path.resolve()
        if path in seen:
            return
        seen.add(path)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s=line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("-r ") or s.startswith("--requirement "):
                parts=s.split(maxsplit=1)
                if len(parts)==2:
                    child=(path.parent/parts[1].strip()).resolve()
                    if child.is_file():
                        _read(child)
                continue
            if s.startswith("-c ") or s.startswith("--constraint "):
                continue
            n=parse_req_name_from_line(s)
            if n:
                roots.append(n)

    _read(Path(req_path))
    out=[]
    seen_names=set()
    for r in roots:
        if r not in seen_names:
            seen_names.add(r)
            out.append(r)
    return out

req_path = sys.argv[1]
roots = read_roots(req_path)

installed = {}
for d in metadata.distributions():
    try:
        name = d.metadata.get("Name") or ""
        ver = d.version or ""
    except Exception:
        continue
    if not name or not ver:
        continue
    n = pep503_normalize(name)
    installed[n] = d

reachable=set()
queue=[r for r in roots if r in installed]
while queue:
    cur=queue.pop()
    if cur in reachable:
        continue
    reachable.add(cur)
    for req_str in list(installed[cur].requires or []):
        dep = parse_name_from_req_string(req_str)
        if dep and dep in installed and dep not in reachable:
            queue.append(dep)

edges={}
for pkg in reachable:
    deps=[]
    for req_str in list(installed[pkg].requires or []):
        dep = parse_name_from_req_string(req_str)
        if dep and dep in reachable:
            deps.append(dep)
    seen=set()
    out=[]
    for d in deps:
        if d not in seen:
            seen.add(d)
            out.append(d)
    edges[pkg]=out

components=[]
for pkg in sorted(reachable):
    dist = installed[pkg]
    msg = dist.metadata
    display_name = msg.get("Name") or pkg
    version = dist.version
    purl = compute_purl(pkg, version)

    summary = (msg.get("Summary") or "").strip()
    lic_name = pick_license_name(msg)
    licenses = [{"license": {"name": lic_name}}] if lic_name else []

    extrefs=[]
    home = safe_url(msg.get("Home-page") or "")
    if home:
        extrefs.append({"type": "website", "url": home})

    for label, url in parse_project_urls(msg):
        u = safe_url(url)
        if u:
            extrefs.append({"type": extref_type(label, u), "url": u})

    dl = safe_url(msg.get("Download-URL") or "")
    if dl:
        extrefs.append({"type": "distribution", "url": dl})

    seen=set()
    dedup=[]
    for er in extrefs:
        key=(er.get("type"), er.get("url"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(er)

    comp = {
        "type": "library",
        "group": "pypi",
        "name": display_name,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
        "description": summary or "",
        "licenses": licenses,
        "externalReferences": dedup,
    }
    components.append(comp)

dependencies=[]
for pkg in sorted(reachable):
    dist = installed[pkg]
    ref = compute_purl(pkg, dist.version)
    depends_on=[]
    for dep in edges.get(pkg, []):
        depends_on.append(compute_purl(dep, installed[dep].version))
    dependencies.append({"ref": ref, "dependsOn": depends_on})

root_refs=[]
for r in roots:
    if r in installed:
        root_refs.append(compute_purl(r, installed[r].version))

print(json.dumps({
    "roots": roots,
    "root_refs": root_refs,
    "components": components,
    "dependencies": dependencies,
    "included": sorted(reachable),
    "excluded": sorted(set(installed.keys()) - reachable),
}, indent=2))
"""
    cp = run([str(py), "-c", helper_code, str(requirements_path.resolve())])
    return json.loads(cp.stdout)


def compute_root_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{pep503_normalize(name)}@{version}"


def main() -> int:
    Config.requirements_txt_file_path = Path(Config.sbom_input_dir, Config.requirements_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    if not Config.requirements_txt_file_path.is_file():
        print(f"ERROR: requirements file not found: {Config.requirements_txt_file_path.resolve()}")
        return 2

    work_dir = Path(tempfile.mkdtemp(prefix="sbom_pypi_"))
    venv_dir = work_dir / "venv"

    try:
        # 1) Create brand-new venv
        run([PYTHON_EXECUTABLE, "-m", "venv", str(venv_dir)])
        py = venv_python(venv_dir)

        # 2) Install requirements into the venv
        #run([str(py), "-m", "pip", "install", "-r", str(Config.requirements_txt_file_path), *PIP_EXTRA_ARGS])

        run([str(py), "-m", "pip", "install",
             "--only-binary=:all:", "--prefer-binary",
             "-r", str(Config.requirements_txt_file_path),
             *PIP_EXTRA_ARGS])

        # 3) Build components/dependencies inside the venv (tree-only, enriched)
        parts = build_sbom_parts_inside_venv(py, Config.requirements_txt_file_path)
        components = parts["components"]
        dependencies = parts["dependencies"]
        root_refs = parts.get("root_refs", [])

        # 4) metadata.component with group/version/bom-ref/purl
        root_purl = compute_root_purl(METADATA_COMPONENT_NAME, METADATA_COMPONENT_VERSION)
        root_bom_ref = root_purl

        # IMPORTANT: do NOT add metadata.component into components list
        # But keep a root dependency node to anchor the graph.
        dependencies.insert(0, {"ref": root_bom_ref, "dependsOn": sorted(set(root_refs))})

        # 5) Write final SBOM in EXACT top-level format/order requested
        out: Dict[str, Any] = {}
        out["bomFormat"] = "CycloneDX"
        out["specVersion"] = SBOM_SPEC_VERSION
        out["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
        out["version"] = 1
        out["metadata"] = {
            "timestamp": now_utc_iso_z(),
            "component": {
                "type": METADATA_COMPONENT_TYPE,
                "name": METADATA_COMPONENT_NAME,
                "group": METADATA_COMPONENT_GROUP,
                "version": METADATA_COMPONENT_VERSION,
                "bom-ref": root_bom_ref,
                "purl": root_purl,
            },
        }
        out["components"] = components
        out["dependencies"] = dependencies

        Config.sbom_output_file_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        if PRINT_DEBUG:
            print(f"Roots: {parts.get('roots', [])}")
            print(f"Root refs (installed): {root_refs}")
            print(f"Included count: {len(parts.get('included', []))}")
            excluded = parts.get("excluded", [])
            print(f"Excluded installed count: {len(excluded)} (example: {excluded[:20]})")

        print(f"SBOM generated: {Config.sbom_output_file_path.resolve()}")
        return 0

    finally:
        shutil.rmtree(work_dir, ignore_errors=False, onerror=_rmtree_onerror)


if __name__ == "__main__":
    raise SystemExit(main())