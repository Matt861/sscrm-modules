#!/usr/bin/env python3
"""
Generate a CycloneDX SBOM.json for PyPI packages listed in requirements.txt.

- Always creates a NEW venv (unique temp dir); never deletes/overwrites any existing venv.
- Reads dependencies from requirements.txt.
- No CLI args; config is hard-coded below.
- Deletes the venv/temp dir after SBOM generation (even on errors).
"""

#from __future__ import annotations

from configuration import Configuration as Config
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


# Pin to a known CLI layout (v4+ uses `environment --outfile ... --output-format ...`)
CYCLONEDX_BOM_VERSION = "7.2.1"  # pip package: cyclonedx-bom

# Optional: schema version & format (CycloneDX tool defaults: schema 1.5, format JSON)
SBOM_SCHEMA_VERSION = "1.6"
SBOM_OUTPUT_FORMAT = "JSON"  # use JSON for SBOM.json

# Optional: extra pip args for restricted environments (uncomment as needed)
# PIP_EXTRA_ARGS = ["--index-url", "https://your.nexus/repository/pypi/simple", "--trusted-host", "your.nexus"]
PIP_EXTRA_ARGS: list[str] = []

PYTHON_EXECUTABLE = sys.executable  # python used to create the venv
# =========================


def cyclonedx_env_command(py: Path, tmp_out: Path, spec_version: str, out_format: str) -> list[str]:
    # Ask the installed tool what flags it supports
    cp = subprocess.run(
        [str(py), "-m", "cyclonedx_py", "environment", "--help"],
        text=True,
        capture_output=True,
    )
    help_text = (cp.stdout or "") + "\n" + (cp.stderr or "")

    # Newer CLI (docs show these)
    has_output_file = "--output-file" in help_text or "-o " in help_text
    has_spec_version = "--spec-version" in help_text or "--sv " in help_text

    if has_output_file and has_spec_version:
        return [
            str(py), "-m", "cyclonedx_py", "environment",
            "--output-file", str(tmp_out),
            "--output-format", out_format,
            "--spec-version", spec_version,
        ]

    # Older CLI fallback (legacy flags)
    return [
        str(py), "-m", "cyclonedx_py", "environment",
        "--outfile", str(tmp_out),
        "--output-format", out_format,
        "--schema-version", spec_version,
    ]


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


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run a command and raise a detailed error on failure (including stdout/stderr)."""
    print(f"\n>> {' '.join(cmd)}")
    cp = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
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


def main() -> int:
    Config.requirements_txt_file_path = Path(Config.sbom_input_dir, Config.requirements_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    if not Config.requirements_txt_file_path.is_file():
        print(f"ERROR: requirements file not found: {Config.requirements_txt_file_path.resolve()}")
        return 2

    work_dir = Path(tempfile.mkdtemp(prefix="sbom_pypi_"))
    venv_dir = work_dir / "venv"

    print(f"Working directory: {work_dir}")
    print(f"Creating venv at:    {venv_dir}")

    try:
        # 1) Create brand-new venv in a unique temp dir
        run([PYTHON_EXECUTABLE, "-m", "venv", str(venv_dir)])
        py = venv_python(venv_dir)

        # 2) Upgrade pip tooling
        run([str(py), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel", *PIP_EXTRA_ARGS])

        # 3) Install CycloneDX tool inside the venv
        run([str(py), "-m", "pip", "install", f"cyclonedx-bom=={CYCLONEDX_BOM_VERSION}", *PIP_EXTRA_ARGS])

        # 4) Install requirements into the venv
        run([str(py), "-m", "pip", "install", "-r", str(Config.requirements_txt_file_path), *PIP_EXTRA_ARGS])

        # 5) Generate SBOM from the installed environment (includes resolved transitive deps)
        tmp_out = work_dir / "SBOM.json"

        # CycloneDX v4+ syntax:
        #   cyclonedx-py environment --outfile <file> --output-format JSON --schema-version 1.6
        # (module form shown below) :contentReference[oaicite:1]{index=1}
        # run([
        #     str(py), "-m", "cyclonedx_py",
        #     "environment",
        #     "--output-file", str(tmp_out),
        #     "--output-format", SBOM_OUTPUT_FORMAT,
        #     "--spec-version", SBOM_SCHEMA_VERSION,
        # ])
        cmd = cyclonedx_env_command(py, tmp_out, SBOM_SCHEMA_VERSION, SBOM_OUTPUT_FORMAT)
        run(cmd)

        # Move SBOM to final location (so it survives temp cleanup)
        out_path = Config.sbom_output_file_path
        tmp_out.replace(out_path)
        print(f"\nSBOM generated: {out_path}")
        return 0

    finally:
        # 6) Delete the venv/temp dir created by this script
        print(f"\nCleaning up temp environment: {work_dir}")
        shutil.rmtree(work_dir, ignore_errors=False, onerror=_rmtree_onerror)


if __name__ == "__main__":
    raise SystemExit(main())