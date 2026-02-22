from pathlib import Path

from configuration import Configuration as Config
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Set

# ----------------------------
# Hard-coded "CLI-like" config
# ----------------------------

# A .txt file listing your TOP-LEVEL RPMs (one per line). Example lines:
# postgresql18-server-18.0-1PGDG.rhel9.x86_64.rpm
# postgresql18-18.0-1PGDG.rhel9.x86_64.rpm
#Config.rpm_txt_file_path = r".\top_level_rpms.txt"

# Folder where you keep RPM files. Put top-level + any child RPMs you have here.
#Config.rpms_folder_path = r".\rpms"

# Output SBOM path
#Config.sbom_output_file_path = r".\sbom-rpm.json"

# Metadata component (the “thing” you are SBOM-ing)
SBOM_ROOT_NAME = "local-rpm-bundle"
SBOM_ROOT_VERSION = "1.0"
SBOM_ROOT_TYPE = "application"

# Optional: put something meaningful here for purl distro qualifier
DISTRO_QUALIFIER = "rhel-9"

# Strict mode:
# True  -> fail if any dependency is missing from local Config.rpms_folder_path
# False -> include what you have; report missing deps but still write SBOM
STRICT_ALL_DEPS_PRESENT = False


# ----------------------------
# Dependencies: pure Python
# ----------------------------

try:
    import rpmfile  # pip install rpmfile
except Exception as e:
    raise RuntimeError(
        "Missing dependency: rpmfile. Install with: pip install rpmfile\n"
        f"Import error: {e}"
    )

try:
    import rpm_vercmp  # pip install rpm-vercmp  (module is rpm_vercmp)
except Exception as e:
    raise RuntimeError(
        "Missing dependency: rpm-vercmp. Install with: pip install rpm-vercmp\n"
        f"Import error: {e}"
    )


# ----------------------------
# RPM sense flags (version ops)
# Values per rpmds.h: LESS=0x02, GREATER=0x04, EQUAL=0x08
# ----------------------------

RPMSENSE_LESS = 0x02
RPMSENSE_GREATER = 0x04
RPMSENSE_EQUAL = 0x08


@dataclass(frozen=True)
class EVR:
    epoch: int
    version: str
    release: str

    def __str__(self) -> str:
        e = self.epoch if self.epoch is not None else 0
        return f"{e}:{self.version}-{self.release}"


@dataclass
class RpmPkg:
    filepath: str
    name: str
    epoch: int
    version: str
    release: str
    arch: str
    summary: str
    description: str
    license: str
    url: str

    provides: List[str]
    provide_versions: List[str]
    provide_flags: List[int]

    requires: List[str]
    require_versions: List[str]
    require_flags: List[int]

    conflicts: List[str]
    conflict_versions: List[str]
    conflict_flags: List[int]

    # --- keep this for version comparisons ---
    def evr(self) -> EVR:
        return EVR(int(self.epoch or 0), self.version, self.release)

    # --- add this for identity / hashing ---
    def nevra(self) -> Tuple[str, int, str, str, str]:
        return (self.name, int(self.epoch or 0), self.version, self.release, self.arch)

    def __hash__(self) -> int:
        return hash(self.nevra())

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RpmPkg) and self.nevra() == other.nevra()

    # (optional) if you already had these, keep yours
    def purl(self) -> str:
        # example: pkg:rpm/<name>@<version>-<release>?arch=<arch>&distro=<distro>
        distro = "rhel-9"
        ver = f"{self.version}-{self.release}"
        return f"pkg:rpm/{self.name}@{ver}?arch={self.arch}&distro={distro}"

    def bom_ref(self) -> str:
        return self.purl()


def _read_lines(path: Path) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        out: List[str] = []
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
        return out


def _safe_str(x) -> str:
    if x is None:
        return ""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", errors="replace")
        except Exception:
            return repr(x)
    return str(x)


def _safe_list(x) -> List:
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]


def parse_evr_string(evr: str) -> EVR:
    """
    Parse common RPM EVR-ish strings.
    Examples:
      "18.0-1PGDG.rhel9" -> epoch=0, version=18.0, release=1PGDG.rhel9
      "1:2.3.4-5"       -> epoch=1, version=2.3.4, release=5
      "2.3.4"           -> epoch=0, version=2.3.4, release=""
    """
    epoch = 0
    s = evr.strip()
    if ":" in s and re.match(r"^\d+:", s):
        epoch_str, s = s.split(":", 1)
        epoch = int(epoch_str)

    if "-" in s:
        version, release = s.split("-", 1)
    else:
        version, release = s, ""

    return EVR(epoch=epoch, version=version, release=release)


def compare_evr(a: EVR, b: EVR) -> int:
    """
    RPM ordering: compare epoch (int), then version (rpmvercmp), then release (rpmvercmp).
    Return: -1 if a<b, 0 if equal, +1 if a>b
    """
    if a.epoch != b.epoch:
        return -1 if a.epoch < b.epoch else 1

    vc = rpm_vercmp.vercmp(a.version, b.version)
    if vc != 0:
        return vc

    # Release can be blank
    return rpm_vercmp.vercmp(a.release or "", b.release or "")


def requirement_satisfied(req_flags: int, required_evr: str, provided_evr: str) -> bool:
    """
    Evaluate (provided_evr) against a versioned requirement (required_evr + flags).
    If flags indicate no version compare, treat as satisfied.
    """
    sense = req_flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL)
    if sense == 0:
        return True  # unversioned requirement, presence is enough

    need = parse_evr_string(required_evr)
    have = parse_evr_string(provided_evr)
    cmp_val = compare_evr(have, need)  # compare provided vs required

    # Interpret flags as constraints on (have ? need)
    ok = True
    if (sense & RPMSENSE_LESS) and not (cmp_val < 0):
        ok = False
    if (sense & RPMSENSE_GREATER) and not (cmp_val > 0):
        ok = False
    if (sense & RPMSENSE_EQUAL) and not (cmp_val == 0):
        ok = False

    # Handle common combos like >= (GREATER|EQUAL) or <= (LESS|EQUAL)
    # The above logic already works because it applies each asserted relation.
    return ok


def load_rpm(path: str) -> RpmPkg:
    with rpmfile.open(path) as rpm:
        h = rpm.headers

        name = _safe_str(h.get("name"))
        version = _safe_str(h.get("version"))
        release = _safe_str(h.get("release"))
        arch = _safe_str(h.get("arch", "noarch"))

        # Epoch: some RPMs store epochnum; default to 0
        epoch_raw = h.get("epochnum", 0)
        try:
            epoch = int(epoch_raw) if epoch_raw is not None else 0
        except Exception:
            epoch = 0

        summary = _safe_str(h.get("summary"))
        description = _safe_str(h.get("description"))
        lic = _safe_str(h.get("license") or h.get("sourcelicense"))
        url = _safe_str(h.get("url"))

        # Dependency tags (arrays aligned by index)
        provides = [ _safe_str(x) for x in _safe_list(h.get("provides")) ]
        provide_versions = [ _safe_str(x) for x in _safe_list(h.get("provideversion")) ]
        provide_flags = []
        for x in _safe_list(h.get("provideflags")):
            try:
                provide_flags.append(int(x))
            except Exception:
                provide_flags.append(0)

        requires = [ _safe_str(x) for x in _safe_list(h.get("requirename")) ]
        require_versions = [ _safe_str(x) for x in _safe_list(h.get("requireversion")) ]
        require_flags = []
        for x in _safe_list(h.get("requireflags")):
            try:
                require_flags.append(int(x))
            except Exception:
                require_flags.append(0)

        conflicts = [ _safe_str(x) for x in _safe_list(h.get("conflictname")) ]
        conflict_versions = [ _safe_str(x) for x in _safe_list(h.get("conflictversion")) ]
        conflict_flags = []
        for x in _safe_list(h.get("conflictflags")):
            try:
                conflict_flags.append(int(x))
            except Exception:
                conflict_flags.append(0)

        # Ensure parallel arrays match length (best-effort)
        def pad_to(lst: List, n: int, pad_val):
            while len(lst) < n:
                lst.append(pad_val)

        pad_to(provide_versions, len(provides), "")
        pad_to(provide_flags, len(provides), 0)

        pad_to(require_versions, len(requires), "")
        pad_to(require_flags, len(requires), 0)

        pad_to(conflict_versions, len(conflicts), "")
        pad_to(conflict_flags, len(conflicts), 0)

        # Some RPMs don't explicitly list "name" in provides; add it as a provided capability
        # with its own EVR for easier matching.
        if name and name not in provides:
            provides.append(name)
            provide_versions.append(str(EVR(epoch, version, release)))
            provide_flags.append(RPMSENSE_EQUAL)

        return RpmPkg(
            filepath=path,
            name=name,
            epoch=epoch,
            version=version,
            release=release,
            arch=arch,
            summary=summary,
            description=description,
            license=lic,
            url=url,
            provides=provides,
            provide_versions=provide_versions,
            provide_flags=provide_flags,
            requires=requires,
            require_versions=require_versions,
            require_flags=require_flags,
            conflicts=conflicts,
            conflict_versions=conflict_versions,
            conflict_flags=conflict_flags,
        )


def build_provides_index(pkgs: List[RpmPkg]) -> Dict[str, List[Tuple[RpmPkg, str]]]:
    """
    capability -> list of (pkg, provided_evr_string)
    """
    idx: Dict[str, List[Tuple[RpmPkg, str]]] = {}
    for p in pkgs:
        for cap, cap_ver in zip(p.provides, p.provide_versions):
            cap = cap.strip()
            if not cap:
                continue
            provided_evr = cap_ver.strip()
            if not provided_evr:
                # If no version attached to the provide capability, use pkg EVR
                provided_evr = str(p.evr())
            idx.setdefault(cap, []).append((p, provided_evr))

        # Also index the package name itself using pkg EVR
        idx.setdefault(p.name, []).append((p, str(p.evr())))

    # Sort each list by highest EVR first so "best" provider is chosen deterministically
    for cap in list(idx.keys()):
        def _key(item: Tuple[RpmPkg, str]) -> Tuple[int, str, str]:
            evr = parse_evr_string(item[1])
            return (evr.epoch, evr.version, evr.release)

        # We'll sort using compare_evr via a simple bubble? Instead, sort by tuple
        # then reverse; rpm ordering isn't lexicographic but rpm_vercmp handles that.
        # We'll keep insertion order stable; choose later by explicit compare.
        idx[cap] = idx[cap]
    return idx


def pick_best_provider(candidates: List[Tuple[RpmPkg, str]]) -> Tuple[RpmPkg, str]:
    """
    Pick the provider with highest EVR (rpm semantics) among candidates.
    """
    best_pkg, best_ver = candidates[0]
    best_evr = parse_evr_string(best_ver)
    for pkg, ver in candidates[1:]:
        evr = parse_evr_string(ver)
        if compare_evr(evr, best_evr) > 0:
            best_pkg, best_ver, best_evr = pkg, ver, evr
    return best_pkg, best_ver


def resolve_dependency_graph(
    top_level: List[RpmPkg],
    all_pkgs: List[RpmPkg],
) -> Tuple[Set[RpmPkg], Dict[str, Set[str]], List[str]]:
    """
    Returns:
      - closure set of packages reachable via requires (only within all_pkgs)
      - deps_map: bom_ref -> set(bom_ref it depends on)
      - missing: human-readable missing dependency lines
    """
    provides_idx = build_provides_index(all_pkgs)
    by_bom: Dict[str, RpmPkg] = {p.bom_ref(): p for p in all_pkgs}

    closure: Set[RpmPkg] = set()
    deps_map: Dict[str, Set[str]] = {}
    missing: List[str] = []

    queue: List[RpmPkg] = list(top_level)

    while queue:
        pkg = queue.pop(0)
        if pkg in closure:
            continue
        closure.add(pkg)

        pkg_ref = pkg.bom_ref()
        deps_map.setdefault(pkg_ref, set())

        # Check each requirement; if satisfied by a local RPM, add edge and enqueue
        for req_name, req_ver, req_flags in zip(pkg.requires, pkg.require_versions, pkg.require_flags):
            req_name = (req_name or "").strip()
            if not req_name:
                continue

            candidates = provides_idx.get(req_name, [])
            if not candidates:
                missing.append(f"{pkg.name} requires {req_name} {req_ver}".strip())
                continue

            chosen_pkg, chosen_prov_ver = pick_best_provider(candidates)

            # If requirement is versioned, validate it
            if req_ver and (req_flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL)):
                if not requirement_satisfied(req_flags, req_ver, chosen_prov_ver):
                    missing.append(
                        f"{pkg.name} requires {req_name} {req_ver} (flags={hex(req_flags)}), "
                        f"but best local provider is {chosen_pkg.name} providing {chosen_prov_ver}"
                    )
                    continue

            # Add dependency edge (only if it resolves to a known local RPM package)
            dep_ref = chosen_pkg.bom_ref()
            deps_map[pkg_ref].add(dep_ref)

            if chosen_pkg not in closure:
                queue.append(chosen_pkg)

    # Also ensure deps_map includes every node in closure
    for p in closure:
        deps_map.setdefault(p.bom_ref(), set())

    return closure, deps_map, missing


def detect_conflicts(closure: Set[RpmPkg]) -> List[str]:
    """
    Detect basic conflicts among packages inside the closure.
    """
    pkgs = list(closure)
    provides_idx = build_provides_index(pkgs)
    conflicts_found: List[str] = []

    for pkg in pkgs:
        for cname, cver, cflags in zip(pkg.conflicts, pkg.conflict_versions, pkg.conflict_flags):
            cname = (cname or "").strip()
            if not cname:
                continue

            candidates = provides_idx.get(cname, [])
            if not candidates:
                continue

            other, other_prov_ver = pick_best_provider(candidates)

            # Ignore self
            if other.name == pkg.name and other.filepath == pkg.filepath:
                continue

            # If conflict is versioned, evaluate; else any match conflicts
            if cver and (cflags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL)):
                if requirement_satisfied(cflags, cver, other_prov_ver):
                    conflicts_found.append(
                        f"{pkg.name} CONFLICTS with {cname} {cver} (flags={hex(cflags)}), "
                        f"and local set provides it via {other.name} ({other_prov_ver})"
                    )
            else:
                conflicts_found.append(
                    f"{pkg.name} CONFLICTS with {cname}, and local set provides it via {other.name}"
                )

    return conflicts_found


def to_component(pkg: RpmPkg) -> Dict:
    licenses = []
    if pkg.license:
        licenses = [{"license": {"name": pkg.license}}]

    external_refs = []
    if pkg.url:
        external_refs.append({"type": "website", "url": pkg.url})

    return {
        "type": "library",
        "name": pkg.name,
        "group": "",  # RPMs don't always have a clean "group"; keep blank unless you map vendor/namespace
        "version": f"{pkg.version}-{pkg.release}",
        "purl": pkg.purl(),
        "bom-ref": pkg.bom_ref(),
        "description": pkg.summary or pkg.description or "",
        "licenses": licenses,
        "externalReferences": external_refs,
    }


def build_sbom(closure: Set[RpmPkg], deps_map: Dict[str, Set[str]]) -> Dict:
    timestamp = datetime.now(timezone.utc).isoformat()

    root_purl = f"pkg:generic/{SBOM_ROOT_NAME}@{SBOM_ROOT_VERSION}"
    root_ref = root_purl

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": "1",
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": SBOM_ROOT_TYPE,
                "name": SBOM_ROOT_NAME,
                "group": "",
                "version": SBOM_ROOT_VERSION,
                "purl": root_purl,
                "bom-ref": root_ref,
                "description": "SBOM generated from local RPM files on Windows",
            },
        },
        "components": [],
        "dependencies": [],
    }

    # Components
    pkgs_sorted = sorted(list(closure), key=lambda p: p.bom_ref())
    sbom["components"] = [to_component(p) for p in pkgs_sorted]

    # Dependencies
    # Add a root node depending on all top-level nodes in deps_map? Here, root depends on all closure.
    sbom["dependencies"].append(
        {"ref": root_ref, "dependsOn": [p.bom_ref() for p in pkgs_sorted]}
    )

    for ref, depends in sorted(deps_map.items(), key=lambda x: x[0]):
        sbom["dependencies"].append({"ref": ref, "dependsOn": sorted(list(depends))})

    return sbom


def main() -> None:
    Config.rpm_txt_file_path = Path(Config.sbom_input_dir, Config.rpm_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")
    Config.rpms_folder_path = Path(Config.sbom_input_dir, Config.rpms_folder_name)

    if not Config.rpm_txt_file_path.exists():
        raise FileNotFoundError(f"Missing input file: {Config.rpm_txt_file_path.resolve()}")

    # Read top-level rpm filenames from .txt
    top_level_names = _read_lines(Config.rpm_txt_file_path)

    # Load all RPMs present in Config.rpms_folder_path (so child deps can be resolved if you have them)
    all_rpm_paths: List[str] = []
    for fn in os.listdir(Config.rpms_folder_path):
        if fn.lower().endswith(".rpm"):
            all_rpm_paths.append(os.path.join(Config.rpms_folder_path, fn))

    if not all_rpm_paths:
        raise RuntimeError(f"No .rpm files found in Config.rpms_folder_path: {Config.rpms_folder_path}")

    all_pkgs: List[RpmPkg] = [load_rpm(p) for p in all_rpm_paths]

    # Map file basename -> pkg for selecting top-level by list file entries
    by_basename: Dict[str, RpmPkg] = {os.path.basename(p.filepath): p for p in all_pkgs}

    top_level: List[RpmPkg] = []
    missing_top_level: List[str] = []
    for name in top_level_names:
        # Allow either full path in file or just filename
        base = os.path.basename(name)
        pkg = by_basename.get(base)
        if not pkg:
            missing_top_level.append(base)
        else:
            top_level.append(pkg)

    if missing_top_level:
        raise RuntimeError(
            "Top-level RPM(s) listed in Config.rpm_txt_file_path not found in Config.rpms_folder_path:\n  "
            + "\n  ".join(missing_top_level)
        )

    closure, deps_map, missing_reqs = resolve_dependency_graph(top_level, all_pkgs)
    conflict_lines = detect_conflicts(closure)

    # Enforce "compatibility"
    problems: List[str] = []
    if missing_reqs:
        problems.append("UNRESOLVED / UNSATISFIED REQUIREMENTS:\n  " + "\n  ".join(missing_reqs))
    if conflict_lines:
        problems.append("CONFLICTS DETECTED:\n  " + "\n  ".join(conflict_lines))

    if problems and STRICT_ALL_DEPS_PRESENT:
        raise RuntimeError("\n\n".join(problems))

    # Build and write SBOM
    sbom = build_sbom(closure, deps_map)

    with open(Config.sbom_output_file_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    print(f"Wrote SBOM: {Config.sbom_output_file_path}")
    print(f"Components (RPMs included): {len(sbom['components'])}")

    if problems:
        print("\nWARNING: Compatibility issues found (STRICT_ALL_DEPS_PRESENT=False):\n")
        print("\n\n".join(problems))


if __name__ == "__main__":
    main()