#!/usr/bin/env python3
"""
Generate a CycloneDX-style SBOM for RPM packages (and ALL resolved child deps).

Design goals (matches your requirements):
- Read top-level packages from a .txt or .spec file (TXT is recommended for runtime RPM SBOMs).
- Ensure the requested set is compatible by doing a single dependency solve for ALL top-level packages together.
- Include *all* resolved child packages as components.
- No CLI args: everything is configured via constants below.
- Output JSON shape matches your example (CycloneDX-ish structure).

Notes:
- This script uses the DNF Python API to resolve dependencies. It does NOT install anything; it only solves.
- You need a working DNF repo configuration (online or internal mirror), or a local repository with repodata.
"""

from configuration import Configuration as Config
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# -------------------------
# Hard-coded "CLI-like" config
# -------------------------

# Input file containing top-level RPMs/package specs (recommended: .txt)
#Config.rpm_txt_file_path = Path("./top_level_rpms.txt")

# Where to look for RPM files if Config.rpm_txt_file_path lists *.rpm filenames (relative paths allowed)
RPM_SEARCH_DIR = Path("./rpms")

# Output SBOM path
#Config.sbom_output_file_path = Path("./sbom.rpm.cdx.json")

# DNF caching (metadata cache directory used by the embedded DNF base)
DNF_CACHE_DIR = Path("./.dnf_cache")

# Dependency solving behavior
LOAD_SYSTEM_REPO = False          # False => solver doesn't assume anything is installed; helps include all deps
INCLUDE_WEAK_DEPS = False         # False => do not pull in Recommends/Suggests (hard deps only)
USE_REPO_CACHE_ONLY = False       # True => load repo metadata only from cache; no network fetch

# Optional: add extra repos programmatically (useful for local repos or custom mirrors).
# Example local repo: {"id": "localrepo", "baseurl": ["file:///path/to/repo"], "enabled": True}
EXTRA_REPOS: List[Dict[str, object]] = []

# SBOM metadata "root" component (the thing that "depends on" your top-level RPMs)
SBOM_ROOT_COMPONENT = {
    "type": "application",
    "name": "rpm-sbom",
    "group": "",
    "version": "1.0",
    "purl": "pkg:generic/rpm-sbom@1.0",
    "bom-ref": "pkg:generic/rpm-sbom@1.0",
    "description": "SBOM generated from a top-level RPM list and resolved via DNF.",
}

# PURL generation settings for rpm packages
PURL_VENDOR_NAMESPACE = "rhel"  # e.g., "rhel", "fedora", "opensuse" (lowercase per common conventions)
PURL_DISTRO_QUALIFIER = "rhel-9"  # optional qualifier; set "" to omit

# If Config.rpm_txt_file_path does not exist, we create it with these example RPMs
DEFAULT_TOP_LEVEL_LINES = [
    "postgresql18-server-18.0-1PGDG.rhel9.x86_64.rpm",
    "postgresql18-18.0-1PGDG.rhel9.x86_64.rpm",
    "postgresql18-libs-18.0-1PGDG.rhel9.x86_64.rpm",
    "postgresql18-contrib-18.0-1PGDG.rhel9.x86_64.rpm",
    "pgaudit_18-18.0-1PGDG.rhel9.x86_64.rpm",
]


# -------------------------
# Helpers / parsing
# -------------------------

SPEC_NAME_RE = re.compile(r"^\s*Name\s*:\s*(\S+)\s*$", re.IGNORECASE)
SPEC_PACKAGE_RE = re.compile(r"^\s*%package\s+(.*)$", re.IGNORECASE)


def _now_iso8601_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_input_file_exists() -> None:
    if Config.rpm_txt_file_path.exists():
        return

    Config.rpm_txt_file_path.write_text(
        "# Auto-generated example top-level RPM list\n"
        "# Lines can be:\n"
        "#   - RPM filenames (preferred): foo-1.2.3-1.el9.x86_64.rpm\n"
        "#   - absolute/relative paths to RPMs\n"
        "#   - or DNF package specs (e.g., 'bash', 'bash.x86_64', 'bash-5.2*')\n\n"
        + "\n".join(DEFAULT_TOP_LEVEL_LINES)
        + "\n",
        encoding="utf-8",
    )
    print(f"[info] Created missing input file at: {Config.rpm_txt_file_path.resolve()}")


def _read_top_level_entries(path: Path) -> List[str]:
    """
    Prefer .txt for runtime SBOMs (lists binary RPMs).
    .spec is supported in a best-effort way (extracts Name and %package names),
    but .spec is primarily about build-time metadata.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()

    if suffix == ".spec":
        names: List[str] = []
        # Main package name
        for line in text.splitlines():
            m = SPEC_NAME_RE.match(line)
            if m:
                names.append(m.group(1).strip())
                break

        # Subpackages from %package sections
        for line in text.splitlines():
            m = SPEC_PACKAGE_RE.match(line)
            if not m:
                continue
            rest = m.group(1).strip()
            # Common forms:
            #   %package libs
            #   %package -n foo-libs
            tokens = rest.split()
            if len(tokens) >= 2 and tokens[0] == "-n":
                names.append(tokens[1])
            elif tokens:
                # "libs", "devel", etc: these are suffixes of Name in many specs,
                # but sometimes are full names. We'll keep as-is.
                names.append(tokens[0])

        # De-dup while preserving order
        seen: Set[str] = set()
        out: List[str] = []
        for n in names:
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out

    # default: .txt-like parsing
    entries: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # allow inline comments: "foo.rpm  # comment"
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        entries.append(line)
    return entries


def _split_local_rpms_vs_specs(entries: Iterable[str]) -> Tuple[List[Path], List[str]]:
    local_rpms: List[Path] = []
    pkg_specs: List[str] = []

    for e in entries:
        if e.lower().endswith(".rpm"):
            p = Path(e)
            if not p.is_absolute():
                p = (RPM_SEARCH_DIR / p).resolve()
            if not p.exists():
                raise FileNotFoundError(f"RPM file not found: {p}")
            local_rpms.append(p)
        else:
            # A DNF package spec: name, name.arch, glob, provides, etc.
            pkg_specs.append(e)

    return local_rpms, pkg_specs


def _rpm_style_version(epoch: int, version: str, release: str) -> str:
    # CycloneDX component.version is a string; for RPM it's common to include epoch if nonzero.
    if epoch and int(epoch) != 0:
        return f"{epoch}:{version}-{release}"
    return f"{version}-{release}"


def _build_rpm_purl(
    name: str,
    epoch: int,
    version: str,
    release: str,
    arch: str,
    vendor_namespace: str,
    distro_qualifier: str,
) -> str:
    # RPM purl type: pkg:rpm/{vendor}/{name}@{version}-{release}?arch=...&epoch=...&distro=...
    # - Keep vendor namespace + name lowercase for stability.
    ns = (vendor_namespace or "").strip().lower()
    nm = (name or "").strip().lower()
    ver = f"{version}-{release}"

    qualifiers: List[Tuple[str, str]] = [("arch", arch)]
    if epoch and int(epoch) != 0:
        qualifiers.append(("epoch", str(int(epoch))))
    if distro_qualifier:
        qualifiers.append(("distro", distro_qualifier))

    q = "&".join(f"{k}={_url_escape(v)}" for k, v in sorted(qualifiers, key=lambda x: x[0]))
    if ns:
        return f"pkg:rpm/{ns}/{nm}@{_url_escape(ver)}?{q}"
    return f"pkg:rpm/{nm}@{_url_escape(ver)}?{q}"


def _url_escape(s: str) -> str:
    # Minimal URL escaping (avoid importing urllib for a tiny subset)
    return (
        s.replace("%", "%25")
        .replace(" ", "%20")
        .replace(":", "%3A")
        .replace("@", "%40")
        .replace("?", "%3F")
        .replace("&", "%26")
        .replace("=", "%3D")
        .replace("/", "%2F")
    )


def _pkg_nevra(pkg) -> str:
    # dnf.package.Package doesn't expose a "nevra" attribute in the public docs,
    # so we construct a stable string.
    # name-epoch:version-release.arch
    return f"{pkg.name}-{int(pkg.epoch)}:{pkg.version}-{pkg.release}.{pkg.arch}"


# -------------------------
# SBOM building
# -------------------------

@dataclass(frozen=True)
class ComponentRef:
    bom_ref: str
    purl: str


def _pkg_to_component(pkg, comp_ref: ComponentRef) -> Dict[str, object]:
    license_str = (pkg.license or "").strip()
    url_str = (pkg.url or "").strip()

    external_refs: List[Dict[str, str]] = []
    if url_str:
        external_refs.append({"type": "website", "url": url_str})

    # If DNF knows a download location, include it as a distribution reference
    try:
        loc = pkg.remote_location()
        if loc:
            external_refs.append({"type": "distribution", "url": str(loc)})
    except Exception:
        pass

    licenses: List[object] = []
    if license_str:
        # Keep this simple but structured.
        licenses.append({"license": {"name": license_str}})

    return {
        "type": "library",
        "name": pkg.name,
        "group": (pkg.group or "") if isinstance(getattr(pkg, "group", ""), str) else "",
        "version": _rpm_style_version(int(pkg.epoch), pkg.version, pkg.release),
        "purl": comp_ref.purl,
        "bom-ref": comp_ref.bom_ref,
        "description": (pkg.description or pkg.summary or "").strip(),
        "licenses": licenses,
        "externalReferences": external_refs,
    }


def _build_dependency_section(
    base,
    install_pkgs: List,
    bom_ref_by_nevra: Dict[str, str],
) -> List[Dict[str, object]]:
    """
    Build a direct dependency list for each package in the resolved set.
    We map each 'requires' entry to the provider package (within install_set) when possible.
    """
    install_nevras: Set[str] = set(bom_ref_by_nevra.keys())
    deps_out: List[Dict[str, object]] = []

    # Cache: requirement-string => list of provider NEVRAs in install_set
    provider_cache: Dict[str, List[str]] = {}

    for pkg in install_pkgs:
        pkg_nevra = _pkg_nevra(pkg)
        pkg_ref = bom_ref_by_nevra[pkg_nevra]

        depends_on: Set[str] = set()

        for req in pkg.requires or []:
            # Skip rpmlib internal requirements (they're satisfied by rpm itself, not a package)
            req_s = str(req)
            if req_s.startswith("rpmlib("):
                continue

            if req_s not in provider_cache:
                providers = []
                try:
                    q = base.sack.query().filter(provides=req)
                    for p in q.run():
                        pn = _pkg_nevra(p)
                        if pn in install_nevras:
                            providers.append(pn)
                except Exception:
                    providers = []
                provider_cache[req_s] = providers

            for prov_nevra in provider_cache[req_s]:
                if prov_nevra == pkg_nevra:
                    continue
                depends_on.add(bom_ref_by_nevra[prov_nevra])

        deps_out.append({"ref": pkg_ref, "dependsOn": sorted(depends_on)})

    return deps_out


def _build_sbom(
    base,
    install_pkgs: List,
    top_level_bom_refs: List[str],
) -> Dict[str, object]:
    bom_ref_by_nevra: Dict[str, str] = {}

    # Precompute bom-refs/purls
    comp_refs: Dict[str, ComponentRef] = {}
    for pkg in install_pkgs:
        purl = _build_rpm_purl(
            name=pkg.name,
            epoch=int(pkg.epoch),
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            vendor_namespace=PURL_VENDOR_NAMESPACE,
            distro_qualifier=PURL_DISTRO_QUALIFIER,
        )
        # Use purl as bom-ref (stable + unique enough)
        nevra = _pkg_nevra(pkg)
        bom_ref_by_nevra[nevra] = purl
        comp_refs[nevra] = ComponentRef(bom_ref=purl, purl=purl)

    components = [_pkg_to_component(pkg, comp_refs[_pkg_nevra(pkg)]) for pkg in install_pkgs]

    dependencies = _build_dependency_section(base, install_pkgs, bom_ref_by_nevra)

    # Add a root dependency node describing "the SBOM subject depends on the top-level packages"
    root_ref = SBOM_ROOT_COMPONENT.get("bom-ref", "sbom-root")
    dependencies.insert(0, {"ref": root_ref, "dependsOn": sorted(set(top_level_bom_refs))})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": "1",
        "metadata": {
            "timestamp": _now_iso8601_utc(),
            "component": SBOM_ROOT_COMPONENT,
        },
        "components": components,
        "dependencies": dependencies,
    }


# -------------------------
# Main: solve + generate
# -------------------------

def main() -> None:
    Config.rpm_txt_file_path = Path(Config.sbom_input_dir, Config.rpm_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.rpm.cdx.json")

    if not Config.rpm_txt_file_path.exists():
        raise FileNotFoundError(f"Missing input file: {Config.rpm_txt_file_path.resolve()}")
    
    #_ensure_input_file_exists()

    entries = _read_top_level_entries(Config.rpm_txt_file_path)
    if not entries:
        raise RuntimeError(f"No top-level entries found in {Config.rpm_txt_file_path}")

    local_rpms, pkg_specs = _split_local_rpms_vs_specs(entries)

    # Lazy import so the script can print a clear message if the environment lacks DNF Python bindings.
    try:
        import dnf  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "This script requires the DNF Python API (import dnf). "
            "On RHEL/Fedora it is commonly provided by a package like 'python3-dnf'. "
            f"Import error: {e}"
        )

    DNF_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    with dnf.Base() as base:
        # Configure DNF
        conf = base.conf
        conf.cachedir = str(DNF_CACHE_DIR)
        try:
            conf.install_weak_deps = bool(INCLUDE_WEAK_DEPS)
        except Exception:
            # Not fatal; older/newer DNF may not expose the same config attribute.
            pass

        # Load repos
        base.read_all_repos()
        for r in EXTRA_REPOS:
            rid = str(r["id"])
            baseurl = [str(u) for u in r.get("baseurl", [])]
            base.repos.add_new_repo(rid, conf, baseurl=baseurl)

        # Fill sack
        if USE_REPO_CACHE_ONLY:
            base.fill_sack_from_repos_in_cache(load_system_repo=LOAD_SYSTEM_REPO)
        else:
            base.fill_sack(load_system_repo=LOAD_SYSTEM_REPO, load_available_repos=True)

        # IMPORTANT: add_remote_rpms MUST be called before adding anything to the goal.
        requested_pkgs = []
        if local_rpms:
            requested_pkgs = base.add_remote_rpms([str(p) for p in local_rpms], strict=True)
            for p in requested_pkgs:
                base.package_install(p, strict=True)

        # Add any non-file package specs
        for spec in pkg_specs:
            base.install(spec, strict=True)

        # Single solve for the whole set => "compatibility check"
        try:
            base.resolve()
        except Exception as e:
            raise RuntimeError(
                "Dependency solve failed. This indicates the requested top-level packages "
                "are not mutually compatible given the enabled repositories and constraints.\n"
                f"Details: {e}"
            )

        install_pkgs = sorted(list(base.transaction.install_set), key=lambda p: (_pkg_nevra(p)))

        # Determine which resolved packages correspond to the *requested* top-level ones
        top_level_bom_refs: List[str] = []
        requested_names: Set[str] = set()

        for p in requested_pkgs:
            requested_names.add(p.name)

        # If .txt included package specs (not rpm files), approximate "requested" by the spec's base token.
        for s in pkg_specs:
            # e.g., "bash.x86_64" => "bash", "bash>=1.2" => "bash>=1.2" (keep simple)
            base_token = re.split(r"[<>=\s]", s.strip(), maxsplit=1)[0]
            base_token = base_token.split(".", 1)[0]
            if base_token:
                requested_names.add(base_token)

        # Map top-level names to bom-refs in the solved install_set
        for p in install_pkgs:
            if p.name in requested_names:
                top_level_bom_refs.append(
                    _build_rpm_purl(
                        name=p.name,
                        epoch=int(p.epoch),
                        version=p.version,
                        release=p.release,
                        arch=p.arch,
                        vendor_namespace=PURL_VENDOR_NAMESPACE,
                        distro_qualifier=PURL_DISTRO_QUALIFIER,
                    )
                )

        sbom = _build_sbom(base, install_pkgs, top_level_bom_refs)

    Config.sbom_output_file_path.write_text(json.dumps(sbom, indent=2, sort_keys=False), encoding="utf-8")
    print(f"[ok] Wrote SBOM: {Config.sbom_output_file_path.resolve()}")
    print(f"[ok] Components (including child deps): {len(sbom['components'])}")
    print(f"[ok] Top-level requested packages matched: {len(set(top_level_bom_refs))}")


if __name__ == "__main__":
    main()