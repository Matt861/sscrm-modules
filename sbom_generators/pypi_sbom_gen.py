#!/usr/bin/env python3
"""
generate_pypi_sbom.py

Generate a CycloneDX JSON SBOM for:
  - the top-level packages in requirements.txt
  - PLUS their full transitive runtime dependency closure
while excluding:
  - unrelated environment packages (pip, setuptools, wheel, etc.)
  - dev/test dependencies introduced via extras markers (extra == "test", "dev", etc.)

Approach (no embedded inner script string):
  Outer mode:
    1) Create isolated venv (temp or user-provided)
    2) Install requirements.txt into that venv
    3) Re-run THIS SAME script using venv's python with --inner
  Inner mode (running inside venv):
    4) Parse requirements.txt top-level packages + requested extras
    5) Build installed distribution dependency graph (importlib.metadata)
    6) Evaluate markers; include only relevant deps
    7) Exclude dev/test-only extras dependencies
    8) Output CycloneDX JSON including only reachable closure

Usage:
  python generate_pypi_sbom.py -r requirements.txt -o sbom.json

Optional:
  --spec-version 1.5          CycloneDX specVersion to write (default: 1.5)
  --venv-dir ./.sbom_venv     Keep/reuse a venv directory
  --keep-venv                Keep temporary venv (only when not using --venv-dir)
  --python /path/to/python   Python to use to create venv
"""

from __future__ import annotations

from configuration import Configuration as Config
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# -----------------------------
# Common parsing helpers
# -----------------------------

_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")


def pep503_normalize(name: str) -> str:
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


# -----------------------------
# requirements.txt parsing (top-level packages + requested extras)
# -----------------------------

def parse_req_line_name_and_extras(line: str) -> Tuple[Optional[str], Set[str]]:
    """
    Extract requirement name and requested extras from a requirements.txt line.

    Examples:
      requests[socks]==2.31.0 -> ("requests", {"socks"})
      name @ https://...      -> ("name", set())
      git+...#egg=name        -> ("name", set())

    Returns (None, set()) for pip options / constraints / includes.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None, set()

    # Strip inline comment (naive but practical)
    if " #" in s:
        s = s.split(" #", 1)[0].strip()

    # Includes/constraints handled by the caller
    if s.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
        return None, set()

    # Common pip options to ignore
    if s.startswith(("--index-url", "--extra-index-url", "--find-links", "-f ", "--trusted-host",
                     "--no-binary", "--only-binary", "--prefer-binary", "--pre", "--use-pep517")):
        return None, set()

    # Editable installs
    if s.startswith(("-e ", "--editable ")):
        if "#egg=" in s:
            egg = s.split("#egg=", 1)[1].strip()
            m = _NAME_RE.match(egg)
            return (pep503_normalize(m.group(1)), set()) if m else (None, set())
        return None, set()

    # VCS / URL with egg
    if "#egg=" in s:
        egg = s.split("#egg=", 1)[1].strip()
        m = _NAME_RE.match(egg)
        return (pep503_normalize(m.group(1)), set()) if m else (None, set())

    # PEP 508 direct reference "name[extras] @ url"
    if " @ " in s:
        left = s.split(" @ ", 1)[0].strip()
        m = _NAME_RE.match(left)
        name = pep503_normalize(m.group(1)) if m else None
        extras: Set[str] = set()
        if "[" in left and "]" in left:
            extras_str = left.split("[", 1)[1].split("]", 1)[0]
            extras = {e.strip().lower() for e in extras_str.split(",") if e.strip()}
        return name, extras

    # Standard "name[extras]..."
    m = _NAME_RE.match(s)
    if not m:
        return None, set()

    name_token = m.group(1)
    extras: Set[str] = set()
    rest = s[len(name_token):]
    if rest.startswith("[") and "]" in rest:
        extras_str = rest[1:rest.index("]")]
        extras = {e.strip().lower() for e in extras_str.split(",") if e.strip()}

    return pep503_normalize(name_token), extras


def parse_requirements_with_extras(req_path: Path, visited: Optional[Set[Path]] = None) -> Dict[str, Set[str]]:
    """
    Resolve '-r other.txt' recursively and return:
      { normalized_top_level_name: {requested_extras...}, ... }
    """
    if visited is None:
        visited = set()

    req_path = req_path.resolve()
    if req_path in visited:
        return {}
    visited.add(req_path)

    base_dir = req_path.parent
    result: Dict[str, Set[str]] = {}

    for raw in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith(("-r ", "--requirement ")):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                child = (base_dir / parts[1].strip()).resolve()
                if child.exists():
                    child_map = parse_requirements_with_extras(child, visited)
                    for k, v in child_map.items():
                        result.setdefault(k, set()).update(v)
            continue

        if line.startswith(("-c ", "--constraint ")):
            continue

        name, extras = parse_req_line_name_and_extras(line)
        if name:
            result.setdefault(name, set()).update(extras)

    return result


# -----------------------------
# Dev/test exclusion (extras-based)
# -----------------------------

DEV_TEST_EXTRAS = {
    "dev", "devel", "development",
    "test", "tests", "testing",
    "lint", "lints", "flake8", "black", "isort", "mypy", "ruff",
    "doc", "docs", "documentation",
    "ci",
    "bench", "benchmark", "perf", "performance",
    "coverage",
}

_EXTRA_EQ_RE = re.compile(r"""extra\s*==\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_EXTRA_IN_RE = re.compile(r"""extra\s+in\s+\{([^}]+)\}""", re.IGNORECASE)


def is_dev_test_extra(extra_name: str) -> bool:
    return extra_name.strip().lower() in DEV_TEST_EXTRAS


def marker_mentions_only_dev_test_extras(marker_str: str) -> bool:
    """
    If a marker references extras, and ALL referenced extras are dev/test-y,
    treat it as dev/test-only and exclude it.
    """
    extras: Set[str] = set(m.group(1).strip().lower() for m in _EXTRA_EQ_RE.finditer(marker_str))

    for m in _EXTRA_IN_RE.finditer(marker_str):
        inner = m.group(1)
        for part in inner.split(","):
            p = part.strip().strip("'\"").lower()
            if p:
                extras.add(p)

    if not extras:
        return False
    return all(is_dev_test_extra(e) for e in extras)


# -----------------------------
# Venv helpers
# -----------------------------

def venv_python_path(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def run(cmd: List[str], *, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


# -----------------------------
# CycloneDX specVersion handling
# -----------------------------

SUPPORTED_CYCLONEDX_SPEC_VERSIONS = {"1.3", "1.4", "1.5", "1.6"}


def validate_spec_version(value: str) -> str:
    v = value.strip()
    if v not in SUPPORTED_CYCLONEDX_SPEC_VERSIONS:
        raise argparse.ArgumentTypeError(
            f"Unsupported CycloneDX specVersion '{v}'. Supported: {', '.join(sorted(SUPPORTED_CYCLONEDX_SPEC_VERSIONS))}"
        )
    return v


# -----------------------------
# Inner logic (runs inside the venv)
# -----------------------------

def _inner_importlib_metadata():
    import importlib.metadata as ilm
    return ilm


def purl_for(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


@dataclass(frozen=True)
class ReqEdge:
    dep_name: str               # normalized dependency name
    dep_extras: Set[str]        # extras requested on the dependency (from "dep[extra]")
    marker_str: str             # marker expression ('' if none)


def build_installed_graph() -> Tuple[Dict[str, object], Dict[str, List[ReqEdge]]]:
    """
    Returns:
      dists: normalized_name -> dist object
      edges: normalized_name -> list of ReqEdge (installed-only target names)
    """
    ilm = _inner_importlib_metadata()

    dists: Dict[str, object] = {}
    for dist in ilm.distributions():
        nm = dist.metadata.get("Name")
        if nm:
            dists[pep503_normalize(nm)] = dist

    installed = set(dists.keys())
    edges: Dict[str, List[ReqEdge]] = {}

    # packaging is normally available in pip environments; use it for correct PEP 508 parsing
    try:
        from packaging.requirements import Requirement
    except Exception:
        Requirement = None  # type: ignore

    for pkg, dist in dists.items():
        out: List[ReqEdge] = []
        for req_str in (dist.requires or []):
            if Requirement is None:
                # fallback: best-effort name-only (no marker/extra parsing)
                m = _NAME_RE.match((req_str or "").strip())
                if not m:
                    continue
                dep = pep503_normalize(m.group(1))
                if dep in installed:
                    out.append(ReqEdge(dep_name=dep, dep_extras=set(), marker_str=""))
                continue

            try:
                r = Requirement(req_str)
            except Exception:
                continue

            dep = pep503_normalize(r.name)
            if dep not in installed:
                continue

            dep_extras = {e.strip().lower() for e in (r.extras or set()) if e.strip()}
            marker_str = str(r.marker) if r.marker else ""
            out.append(ReqEdge(dep_name=dep, dep_extras=dep_extras, marker_str=marker_str))

        # stable de-dupe
        seen: Set[Tuple[str, str, Tuple[str, ...]]] = set()
        dedup: List[ReqEdge] = []
        for e in out:
            key = (e.dep_name, e.marker_str, tuple(sorted(e.dep_extras)))
            if key not in seen:
                seen.add(key)
                dedup.append(e)
        edges[pkg] = dedup

    return dists, edges


def inner_generate_sbom(requirements: Path, output: Path, spec_version: str) -> int:
    # Parse top-level requirements + requested extras
    top_map = parse_requirements_with_extras(requirements)  # name -> extras set
    top_names = list(top_map.keys())

    dists, edges = build_installed_graph()
    installed = set(dists.keys())

    print(f"[debug] top-level parsed: {len(top_map)} -> {sorted(top_map.keys())[:20]}", file=sys.stderr)
    print(f"[debug] installed dists: {len(installed)} (sample: {sorted(installed)[:20]})", file=sys.stderr)

    # Marker evaluator (packaging)
    try:
        from packaging.requirements import Requirement
        from packaging.markers import default_environment
    except Exception:
        Requirement = None  # type: ignore
        default_environment = None  # type: ignore

    # Optional tooling denylist. If you want pip/setuptools/wheel to NEVER appear unless top-level:
    TOOLING_DENYLIST = {"pip", "setuptools", "wheel"}

    # extras requested per package (from requirements.txt + propagated dep_extras),
    # excluding dev/test extras
    extras_needed: Dict[str, Set[str]] = {
        n: {e for e in extras if not is_dev_test_extra(e)}
        for n, extras in top_map.items()
        if n in installed
    }

    # Start closure at top-level packages that are installed
    closure: Set[str] = set(extras_needed.keys())
    resolved_deps: Dict[str, List[str]] = {n: [] for n in closure}

    q: List[str] = list(closure)
    i = 0

    while i < len(q):
        pkg = q[i]
        i += 1

        pkg_extras = extras_needed.get(pkg, set())
        resolved: List[str] = []

        for edge in edges.get(pkg, []):
            dep = edge.dep_name
            if dep not in installed:
                continue

            # Tooling filter (keeps tooling out unless explicitly top-level)
            if dep in TOOLING_DENYLIST and dep not in top_map:
                continue

            # Marker filtering
            if edge.marker_str:
                marker_lower = edge.marker_str.lower()

                if "extra" in marker_lower:
                    # If marker references only dev/test extras -> drop
                    if marker_mentions_only_dev_test_extras(edge.marker_str):
                        continue

                    # Only include extra-gated deps if some *requested* non-dev/test extra satisfies marker
                    include = False
                    if Requirement is not None and default_environment is not None and pkg_extras:
                        try:
                            r = Requirement(f"{dep}; {edge.marker_str}")
                        except Exception:
                            r = None

                        if r and r.marker:
                            base_env = default_environment()
                            for ex in sorted(pkg_extras):
                                env = dict(base_env)
                                env["extra"] = ex
                                if r.marker.evaluate(env):
                                    include = True
                                    break

                    if not include:
                        continue

                else:
                    # Non-extra marker: evaluate against environment
                    if Requirement is not None and default_environment is not None:
                        try:
                            r = Requirement(f"{dep}; {edge.marker_str}")
                        except Exception:
                            r = None
                        if r and r.marker:
                            env = default_environment()
                            env["extra"] = ""
                            if not r.marker.evaluate(env):
                                continue
                    # If packaging unavailable, best-effort include

            # Include dependency
            resolved.append(dep)

            # Propagate explicit dependency extras requested via "dep[extra]" (excluding dev/test extras)
            if edge.dep_extras:
                wanted = {e for e in edge.dep_extras if not is_dev_test_extra(e)}
                if wanted:
                    extras_needed.setdefault(dep, set()).update(wanted)

            if dep not in closure:
                closure.add(dep)
                q.append(dep)
                resolved_deps.setdefault(dep, [])

        resolved_deps[pkg] = sorted(set(resolved))

    print(f"[debug] top-level present in env: {len(extras_needed)} -> {sorted(extras_needed.keys())[:20]}",
          file=sys.stderr)
    print(f"[debug] closure size: {len(closure)}", file=sys.stderr)

    # ----- Build CycloneDX JSON from closure -----
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    bomref_by_name: Dict[str, str] = {}
    components: List[dict] = []

    for name in sorted(closure):
        dist = dists[name]
        version = getattr(dist, "version", None) or dist.metadata.get("Version", "0")
        bom_ref = purl_for(name, version)
        bomref_by_name[name] = bom_ref
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": bom_ref,
            "bom-ref": bom_ref,
        })

    dependencies: List[dict] = []
    for name in sorted(closure):
        deps = [bomref_by_name[d] for d in resolved_deps.get(name, []) if d in closure]
        dependencies.append({"ref": bomref_by_name[name], "dependsOn": deps})

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {"type": "application", "name": "requirements-sbom"},
        },
        "components": components,
        "dependencies": dependencies,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    missing = [n for n in top_names if n not in installed]
    if missing:
        print("WARNING: Some top-level requirements could not be matched to installed distributions:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)

    return 0


# -----------------------------
# Outer orchestration
# -----------------------------

def outer_run(requirements: Path, output: Path, venv_dir: Optional[Path], keep_venv: bool,
              python_for_venv: Optional[Path], spec_version: str) -> int:
    requirements = requirements.resolve()
    output = output.resolve()

    if not requirements.exists():
        print(f"ERROR: requirements file not found: {requirements}", file=sys.stderr)
        return 2

    created_tmp = False
    if venv_dir:
        venv_dir = venv_dir.resolve()
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
    else:
        venv_dir = Path(tempfile.mkdtemp(prefix="sbom_venv_"))
        created_tmp = True

    try:
        py = str(python_for_venv.resolve()) if python_for_venv else sys.executable
        vpy = venv_python_path(venv_dir)

        if not vpy.exists():
            print(f"[+] Creating venv: {venv_dir}")
            run([py, "-m", "venv", str(venv_dir)])

        vpy = venv_python_path(venv_dir)
        if not vpy.exists():
            print("ERROR: venv python not found after creation.", file=sys.stderr)
            return 2

        print(f"[+] Installing requirements into venv: {requirements}")
        run([str(vpy), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(requirements)])

        print("[+] Generating SBOM (re-invoking script inside venv)")
        script_path = Path(__file__).resolve()

        # inner_env = os.environ.copy()
        # inner_env["SBOM_INNER"] = "1"
        #
        # run(
        #     [
        #         str(vpy), str(script_path),
        #         "--inner",
        #         "--spec-version", spec_version,
        #         "-r", str(requirements),
        #         "-o", str(output),
        #     ],
        #     env=inner_env,
        # )

        inner_env = os.environ.copy()
        inner_env["SBOM_INNER"] = "1"

        run(
            [str(vpy), str(script_path),
             "--inner",
             "--spec-version", spec_version,
             "-r", str(requirements),
             "-o", str(output)],
            env=inner_env
        )

        print(f"[✓] SBOM written to: {output}")
        return 0

    finally:
        if created_tmp and not keep_venv:
            shutil.rmtree(venv_dir, ignore_errors=True)


def main() -> int:
    # ap = argparse.ArgumentParser()
    # # ap.add_argument("-r", "--requirements", required=True, type=Path, help="Path to requirements.txt")
    # # ap.add_argument("-o", "--output", required=True, type=Path, help="Output SBOM JSON path")
    # ap.add_argument("--requirements", type=Path, help="Path to requirements.txt")
    # ap.add_argument( "--output", type=Path, help="Output SBOM JSON path")
    #
    # ap.add_argument("--spec-version", type=validate_spec_version, default="1.5",
    #                 help="CycloneDX specVersion to write (default: 1.5). Supported: 1.3, 1.4, 1.5, 1.6")
    #
    # ap.add_argument("--venv-dir", type=Path, default=None,
    #                 help="Use/keep a specific venv directory (created if missing)")
    # ap.add_argument("--keep-venv", action="store_true",
    #                 help="Keep the temporary venv (ignored if --venv-dir is used)")
    # ap.add_argument("--python", type=Path, default=None,
    #                 help="Python executable to use for venv creation (default: current python)")
    # ap.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    #
    # args = ap.parse_args()

    Config.requirements_txt_file_path = Path(Config.sbom_input_dir, Config.requirements_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")
    keep_venv = False
    python = None
    venv_dir = None
    inner = False
    spec_version = "1.5"

    #is_inner = inner or os.environ.get("SBOM_INNER") == "1"

    # if is_inner:
    #     return inner_generate_sbom(Config.requirements_txt_file_path, Config.sbom_output_file_path, spec_version)

    if inner:
        # Safety: ensure inner runs only when spawned by outer_run
        if os.environ.get("SBOM_INNER") != "1":
            raise SystemExit("Refusing to run --inner without SBOM_INNER=1 (must be spawned by outer_run).")
        return inner_generate_sbom(Config.requirements_txt_file_path, Config.sbom_output_file_path, spec_version)

    # if inner:
    #     return inner_generate_sbom(Config.requirements_txt_file_path, Config.sbom_output_file_path, spec_version)

    return outer_run(
        requirements=Config.requirements_txt_file_path,
        output=Config.sbom_output_file_path,
        venv_dir=venv_dir,
        keep_venv=keep_venv,
        python_for_venv=python,
        spec_version=spec_version,
    )

    # if args.inner:
    #     return inner_generate_sbom(args.requirements, args.output, args.spec_version)
    #
    # return outer_run(
    #     requirements=args.requirements,
    #     output=args.output,
    #     venv_dir=args.venv_dir,
    #     keep_venv=args.keep_venv,
    #     python_for_venv=args.python,
    #     spec_version=args.spec_version,
    # )


if __name__ == "__main__":
    raise SystemExit(main())