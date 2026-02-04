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
import argparse
import shutil
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


def find_generated_files(fmt: str) -> list[Path]:
    exts = []
    if fmt == "json":
        exts = ["json"]
    elif fmt == "xml":
        exts = ["xml"]
    elif fmt == "all":
        exts = ["json", "xml"]

    results: list[Path] = []
    for ext in exts:
        p = Path(f"{Config.sbom_output_file_path}.{ext}")
        if p.exists():
            results.append(p)
    return results


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
    parser = argparse.ArgumentParser(description="Generate a CycloneDX SBOM for a Maven project.")
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Path to the Maven project root (directory containing pom.xml). Default: .",
    )
    parser.add_argument(
        "--pom",
        default=None,
        help="Optional path to pom.xml (relative to project-dir or absolute). If omitted, uses project-dir/pom.xml.",
    )
    parser.add_argument(
        "--goal",
        choices=["makeAggregateBom", "makeBom"],
        default="makeAggregateBom",
        help="CycloneDX goal to run. Default: makeAggregateBom (recommended for multi-module).",
    )
    parser.add_argument(
        "--plugin-version",
        default="2.9.1",
        help="CycloneDX Maven plugin version. Default: 2.9.1",
    )
    parser.add_argument(
        "--format",
        choices=["json", "xml", "all"],
        default="json",
        help="SBOM output format. Default: json",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for the SBOM. Default: <project>/target",
    )
    parser.add_argument(
        "--output-name",
        default="bom",
        help="Output filename WITHOUT extension. Default: bom",
    )
    parser.add_argument(
        "--include-test-scope",
        action="store_true",
        help="Include test-scoped dependencies in the SBOM.",
    )
    parser.add_argument(
        "--mvn",
        default="mvn.cmd",
        help="Maven executable (e.g., mvn or ./mvnw). Default: mvn",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run Maven in offline mode (-o). Note: plugin may require online mode depending on your setup.",
    )
    parser.add_argument(
        "--no-skip-tests-flag",
        action="store_true",
        help="By default, the script passes -DskipTests. Use this flag to NOT set -DskipTests.",
    )

    args = parser.parse_args()

    if Config.sbom_gen_input_dir:
        args.project_dir = Config.sbom_gen_input_dir
    if Config.sbom_gen_input_file:
        args.pom = Config.sbom_gen_input_file
    if Config.sbom_gen_output_dir:
        args.output_dir = Config.sbom_output_dir
    if Config.sbom_gen_output_file:
        args.output_name = Config.sbom_gen_output_file
    if args.format:
        Config.sbom_extension = f".{args.format}"

    Config.sbom_output_file_path = Path(Config.sbom_output_dir, args.output_name)

    #project_dir = Path(args.project_dir).resolve() if args.project_dir else (Path(Config.root_dir, "input/sbom_gen"))
    project_dir = Path(args.project_dir).resolve()
    if not project_dir.exists():
        print(logger.error(f"ERROR: project-dir does not exist: {project_dir}"), file=sys.stderr)
        sys.exit()

    #pom_path = Path(args.project_dir, args.pom).resolve() if args.pom else (Path(Config.root_dir, "input/sbom_gen/pom.xml"))
    pom_path = Path(args.pom).resolve() if args.pom else (project_dir / "pom.xml")
    if not pom_path.exists():
        print(logger.error(f"ERROR: pom.xml not found: {pom_path}"), file=sys.stderr)
        sys.exit()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Ensure Maven is available
    if args.mvn != "./mvnw" and shutil.which(args.mvn) is None:
        print(logger.error(
            f"ERROR: Maven executable not found: {args.mvn}\n"
            f"Tip: use --mvn ./mvnw if your project includes Maven Wrapper."),
            file=sys.stderr,
        )
        sys.exit()

    # Build the Maven command
    plugin = f"org.cyclonedx:cyclonedx-maven-plugin:{args.plugin_version}:{args.goal}"

    mvn_exec = resolve_maven_executable(args.mvn, project_dir)

    cmd = [mvn_exec, "-f", str(pom_path), plugin]
    if args.offline:
        cmd.append("-o")

    # Common flags
    cmd += [
        f"-DoutputFormat={args.format}",
        f"-DoutputName={args.output_name}",
        f"-DoutputDirectory={args.output_dir}",
    ]

    if args.include_test_scope:
        cmd.append("-DincludeTestScope=true")

    if not args.no_skip_tests_flag:
        cmd.append("-DskipTests")

    # Run
    run(cmd, cwd=project_dir, log_file=Path(Config.root_dir, "logs/maven_sbom_gen_subprocess.log"))

    # Confirm outputs
    generated = find_generated_files(args.format)
    if generated:
        print("\nSBOM generated:")
        for p in generated:
            print(f"   - {p}")
    else:
        # Some builds/plugins may place files elsewhere depending on configuration.
        print(logger.error(
            "\nMaven finished, but expected SBOM file(s) not found in the configured output directory.\n"
            f"Look under: {args.output_dir}\n"
            "If this is a multi-module build, ensure you're running from the reactor root, or try --goal makeBom."),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
