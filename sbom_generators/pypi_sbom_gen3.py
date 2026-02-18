#!/usr/bin/env python3
"""
Generate a CycloneDX SBOM.json for PyPI packages listed in requirements.txt,
in a format that Dependency-Track accepts.

Key Dependency-Track compatibility choices:
- Default to CycloneDX spec 1.5 (DT supports import since v4.9.0).
  (DT supports 1.6 since v4.12.0; set SBOM_SPEC_VERSION = "1.6" if desired.)
- Optionally sanitize licenses to avoid schema validation rejections related to license IDs/expressions.
  (DT rejects BOMs that fail schema validation starting v4.11.0.)

Also:
- Always creates a NEW temp venv, installs requirements, generates SBOM, then deletes the venv/temp dir.
- No command line arguments; all config is hard-coded below.
"""

#from __future__ import annotations

from configuration import Configuration as Config
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


# CycloneDX tool (CLI provided by pip package "cyclonedx-bom")
CYCLONEDX_BOM_VERSION = "7.2.1"

# Dependency-Track-friendly defaults:
SBOM_OUTPUT_FORMAT = "JSON"

# Best compatibility across DT versions: 1.5 (DT supports since 4.9.0).
# If you KNOW you run DT >= 4.12.0, you can set to "1.6".
SBOM_SPEC_VERSION = "1.3"

# Highly recommended for "always uploads successfully" behavior:
# Converts license.id / license.expression -> license.name (schema-safe).
SANITIZE_LICENSES_FOR_DTRACK = True

# Optional: extra pip args for restricted environments (uncomment as needed)
# PIP_EXTRA_ARGS = ["--index-url", "https://your.nexus/repository/pypi/simple", "--trusted-host", "your.nexus"]
PIP_EXTRA_ARGS: list[str] = []

PYTHON_EXECUTABLE = sys.executable
# =========================


def _rmtree_onerror(func, path, exc_info):
    # Windows sometimes marks files read-only; clear and retry
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    try:
        func(path)
    except Exception:
        pass


def run(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a command and raise a detailed error on failure (including stdout/stderr)."""
    print(f"\n>> {' '.join(cmd)}")
    cp = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
    )
    if cp.stdout:
        print(cp.stdout)
    if cp.stderr:
        print(cp.stderr, file=sys.stderr)

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


def build_cyclonedx_env_cmd(py: Path, out_file: Path, spec_version: str, out_format: str) -> list[str]:
    """
    Build a cyclonedx-py 'environment' command compatible with whichever CLI version is installed.
    We inspect `environment --help` to pick supported flag names.
    """
    help_cp = subprocess.run(
        [str(py), "-m", "cyclonedx_py", "environment", "--help"],
        text=True,
        capture_output=True,
    )
    help_text = (help_cp.stdout or "") + "\n" + (help_cp.stderr or "")

    # Output file flag: newer uses --output-file, older uses --outfile, some support -o
    if "--output-file" in help_text:
        out_flag = "--output-file"
    elif "--outfile" in help_text:
        out_flag = "--outfile"
    else:
        out_flag = "-o"  # common short flag

    # Spec version flag: newer uses --spec-version, older uses --schema-version
    if "--spec-version" in help_text:
        ver_flag = "--spec-version"
    elif "--schema-version" in help_text:
        ver_flag = "--schema-version"
    else:
        # If the tool doesn't expose a version flag, omit it and accept its default.
        ver_flag = ""

    cmd = [
        str(py), "-m", "cyclonedx_py",
        "environment",
        out_flag, str(out_file),
        "--output-format", out_format,
    ]
    if ver_flag:
        cmd.extend([ver_flag, spec_version])

    return cmd


def sanitize_licenses_for_dependency_track(bom: Any) -> None:
    """
    Converts licenses to schema-safe form:
      - If a license entry has `license.id`, rewrite as `license.name` and remove `id`.
      - If a license entry has `expression`, rewrite as `license.name` and remove `expression`.

    This avoids validation failures caused by strict/dated SPDX ID enums or expression parsing.
    """
    if isinstance(bom, dict):
        # Rewrite licenses at this level if present
        if "licenses" in bom and isinstance(bom["licenses"], list):
            sanitized: list[dict[str, Any]] = []
            for entry in bom["licenses"]:
                if not isinstance(entry, dict):
                    continue

                if "expression" in entry and entry.get("expression"):
                    sanitized.append({"license": {"name": str(entry["expression"])}})
                    continue

                lic = entry.get("license")
                if isinstance(lic, dict):
                    name = lic.get("name") or lic.get("id")
                    if name:
                        sanitized.append({"license": {"name": str(name)}})
                        continue

            if sanitized:
                bom["licenses"] = sanitized
            else:
                bom.pop("licenses", None)

        # Recurse
        for v in bom.values():
            sanitize_licenses_for_dependency_track(v)

    elif isinstance(bom, list):
        for item in bom:
            sanitize_licenses_for_dependency_track(item)


def main() -> int:
    Config.requirements_txt_file_path = Path(Config.sbom_input_dir, Config.requirements_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    if not Config.requirements_txt_file_path.is_file():
        print(f"ERROR: requirements file not found: {Config.requirements_txt_file_path.resolve()}")
        return 2

    # Unique temp dir so we never collide with any existing venv.
    work_dir = Path(tempfile.mkdtemp(prefix="sbom_pypi_"))
    venv_dir = work_dir / "venv"

    print(f"Working directory: {work_dir}")
    print(f"Creating venv at:    {venv_dir}")

    try:
        # 1) Create brand-new venv
        run([PYTHON_EXECUTABLE, "-m", "venv", str(venv_dir)])
        py = venv_python(venv_dir)

        # 2) Upgrade pip tooling
        run([str(py), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel", *PIP_EXTRA_ARGS])

        # 3) Install CycloneDX generator
        run([str(py), "-m", "pip", "install", f"cyclonedx-bom=={CYCLONEDX_BOM_VERSION}", *PIP_EXTRA_ARGS])

        # 4) Install requirements into the venv
        run([str(py), "-m", "pip", "install", "-r", str(Config.requirements_txt_file_path), *PIP_EXTRA_ARGS])

        # 5) Generate SBOM from installed environment (captures resolved transitive deps)
        tmp_out = work_dir / "SBOM.json"
        cmd = build_cyclonedx_env_cmd(py, tmp_out, SBOM_SPEC_VERSION, SBOM_OUTPUT_FORMAT)
        run(cmd)

        # 6) Optional: sanitize SBOM for Dependency-Track upload acceptance
        if SANITIZE_LICENSES_FOR_DTRACK:
            data = json.loads(tmp_out.read_text(encoding="utf-8"))
            sanitize_licenses_for_dependency_track(data)

            # Ensure minimal CycloneDX identifiers remain intact
            # (cyclonedx tool should already set these correctly)
            if data.get("bomFormat") != "CycloneDX":
                raise RuntimeError(f"Unexpected bomFormat: {data.get('bomFormat')!r}")
            if "specVersion" not in data:
                raise RuntimeError("Missing specVersion in generated BOM")

            tmp_out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        # 7) Move SBOM to final location (so it survives temp cleanup)
        out_path = Config.sbom_output_file_path.resolve()
        tmp_out.replace(out_path)
        print(f"\nSBOM generated: {out_path}")
        print(f"Spec version:   {SBOM_SPEC_VERSION} (change SBOM_SPEC_VERSION if needed)")
        return 0

    finally:
        # 8) Delete the venv/temp dir created by this script
        print(f"\nCleaning up temp environment: {work_dir}")
        shutil.rmtree(work_dir, ignore_errors=False, onerror=_rmtree_onerror)


if __name__ == "__main__":
    raise SystemExit(main())