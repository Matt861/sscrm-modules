#!/usr/bin/env python3
"""
Generate a CycloneDX SBOM for a Maven project by invoking the CycloneDX Maven plugin.

Defaults to an aggregate BOM (best for multi-module builds).

Docs:
- CycloneDX Maven plugin overview: https://cyclonedx.github.io/cyclonedx-maven-plugin/  (see sources)
- makeAggregateBom parameters: outputFormat/outputName/outputDirectory/includeTestScope
"""

from __future__ import annotations
from configuration import Configuration as Config
from loggers.maven_sbom_gen_logger import maven_sbom_gen_logger as logger
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], cwd: Path, log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with log_file.open("w", encoding="utf-8") as f:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # combine
            text=True,
            bufsize=1,                # line-buffered
            universal_newlines=True,
        )

        assert proc.stdout is not None
        for line in proc.stdout:
            # write to file
            f.write(line)
            # and to console
            sys.stdout.write(line)

        proc.wait()

    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


# def find_generated_files(fmt: str) -> list[Path]:
#     exts = []
#     if fmt == "json":
#         exts = ["json"]
#     elif fmt == "xml":
#         exts = ["xml"]
#     elif fmt == "all":
#         exts = ["json", "xml"]
#
#     results: list[Path] = []
#     for ext in exts:
#         p = Path(f"{Config.sbom_output_file_path}.{ext}")
#         if p.exists():
#             results.append(p)
#     return results


import os
import shutil
from pathlib import Path

def resolve_maven_executable(mvn_arg: str, project_dir: Path) -> str:
    """
    Resolve a usable Maven executable on Windows/Linux/macOS.

    - If mvn_arg points to an existing file, use it.
    - If mvn_arg is mvnw / ./mvnw, prefer mvnw.cmd on Windows.
    - If mvn_arg is 'mvn', resolve via PATH to an absolute executable.
    """
    # If user passed an explicit path, honor it
    p = Path(mvn_arg)
    if p.exists():
        return str(p.resolve())

    # Windows wrapper name
    is_windows = os.name == "nt"

    # If user requested Maven Wrapper, try the correct filename
    mvn_lower = mvn_arg.replace("\\", "/").lower()
    if mvn_lower in ("./mvnw", "mvnw", "mvnw.sh"):
        if is_windows:
            cand = project_dir / "mvnw.cmd"
            if cand.exists():
                return str(cand.resolve())
            cand = project_dir / "mvnw.bat"
            if cand.exists():
                return str(cand.resolve())
        else:
            cand = project_dir / "mvnw"
            if cand.exists():
                return str(cand.resolve())

        raise FileNotFoundError(
            f"Maven Wrapper requested but not found in {project_dir} "
            f"(expected mvnw.cmd on Windows or mvnw on Unix)."
        )

    # Otherwise resolve from PATH (works for mvn / mvn.cmd / mvn.bat)
    resolved = shutil.which(mvn_arg)
    if resolved:
        return resolved

    raise FileNotFoundError(
        f"Could not find Maven executable '{mvn_arg}'. "
        f"On Windows: install Maven and add it to PATH, or use --mvn mvnw.cmd if the project has Maven Wrapper."
    )


def main() -> None:
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"

    if not Config.sbom_input_dir.exists():
        print(logger.error(f"ERROR: sbom input directory does not exist: {Config.sbom_input_dir}"), file=sys.stderr)
        sys.exit()

    pom_path = Path(Config.sbom_input_dir, Config.sbom_input_file)
    if not pom_path.exists():
        print(logger.error(f"ERROR: pom.xml not found: {pom_path}"), file=sys.stderr)
        sys.exit()

    Config.project_output_dir.mkdir(parents=True, exist_ok=True)

    # Ensure Maven is available
    if Config.maven_command != "./mvnw" and shutil.which(Config.maven_command) is None:
        print(logger.error(
            f"ERROR: Maven executable not found: {Config.maven_command}\n"
            f"Tip: use --mvn ./mvnw if your project includes Maven Wrapper."),
            file=sys.stderr,
        )
        sys.exit()

    # Build the Maven command
    plugin = f"org.cyclonedx:cyclonedx-maven-plugin:{Config.cyclonedx_maven_plugin_version}:{Config.maven_goal}"

    mvn_exec = resolve_maven_executable(Config.maven_command, Config.sbom_input_dir)

    cmd = [mvn_exec, "-f", str(pom_path), plugin]
    if Config.maven_offline_mode:
        cmd.append("-o")

    # Common flags
    cmd += [
        f"-DoutputFormat={Config.sbom_format}",
        f"-DoutputName={Config.sbom_output_file_name}",
        f"-DoutputDirectory={Config.project_output_dir}",
    ]

    if Config.maven_include_test_scope:
        cmd.append("-DincludeTestScope=true")

    if Config.maven_skip_tests_flag:
        cmd.append("-DskipTests")

    # Run
    run(cmd, cwd=Config.sbom_input_dir, log_file=Path(Config.log_dir, Config.maven_sbom_gen_log_file_name))

    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")

    # Confirm outputs
    if Config.sbom_output_file_path.exists():
        print(f"SBOM generated: {Config.sbom_output_file_path}")
        # for p in generated:
        #     print(f"   - {p}")
    else:
        # Some builds/plugins may place files elsewhere depending on configuration.
        print(logger.error(
            "\nMaven finished, but expected SBOM file(s) not found in the configured output directory.\n"
            f"Look under: {Config.project_output_dir}\n"
            "If this is a multi-module build, ensure you're running from the reactor root, or try --goal makeBom."),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
