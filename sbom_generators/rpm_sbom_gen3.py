#!/usr/bin/env python3
"""
Windows-only RPM SBOM generator using LOCAL repodata/ (RPM-MD).
- No dnf, no rpm CLI, no WSL, no containers.
- Uses repodata/repomd.xml -> primary.xml.* (and optionally filelists.xml.*)
- Resolves dependency closure and downloads missing RPMs based on metadata locations.

Prereq:
- You already ran the "bootstrap repodata" downloader script and now have:
    <Config.rpm_local_repo>\repodata\repomd.xml
    <Config.rpm_local_repo>\repodata\<hash>-primary.xml.gz  (etc)

Edit CONFIG below; no CLI args.
"""

from configuration import Configuration as Config
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET


# ----------------------------
# CONFIG (hard-coded settings)
# ----------------------------

# Top-level input list (.txt recommended). Can contain:
#   - RPM filenames: name-ver-rel.arch.rpm
#   - package names: name  or name.x86_64
#Config.rpm_txt_file_path = Path(r".\top_level_rpms.txt")

# Local repo directory produced by your bootstrap script:
#   <Config.rpm_local_repo>\repodata\repomd.xml
#Config.rpm_local_repo = Path(r"C:\sbom\repos\pgdg18-rhel9-x86_64")

# Remote base URL corresponding to that repo (used to download RPMs):
REPO_BASE_URL = "https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-9-x86_64/"

# Where to store downloaded RPMs (child packages you didn't already have)
#Config.rpm_cache_dir = Path(r".\rpm_cache")

# Output SBOM
#Config.sbom_output_file_path = Path(r".\sbom.rpm.cdx.json")

# Arch policy (keep consistent with your RPM set)
TARGET_ARCH = "x86_64"
ALLOW_NOARCH = True

# If True, also parse filelists.xml.* and satisfy file-path requires (e.g. /usr/bin/env)
# Warning: filelists can be very large.
ENABLE_FILELISTS_INDEX = True

# If True, download the RPM files for every resolved package (top-level + deps)
DOWNLOAD_RESOLVED_RPMS = True

# If True, fail the run if ANY dependency cannot be satisfied by this repo's repodata.
STRICT_RESOLUTION = True

# CycloneDX-ish metadata
SBOM_SPEC_VERSION = "1.5"
SBOM_VERSION = "1"

SBOM_ROOT_COMPONENT = {
    "type": "application",
    "name": "rpm-sbom",
    "group": "",
    "version": "1.0",
    "purl": "pkg:generic/rpm-sbom@1.0",
    "bom-ref": "pkg:generic/rpm-sbom@1.0",
    "description": "SBOM generated on Windows from local repodata/ and a top-level RPM list.",
}

# PURL qualifiers
PURL_NAMESPACE = "pgdg"
PURL_DISTRO = "rhel-9"


# ----------------------------
# Data models
# ----------------------------

@dataclass(frozen=True)
class EVR:
    epoch: int
    ver: str
    rel: str

@dataclass(frozen=True)
class Capability:
    name: str
    flags: Optional[str]  # "EQ","GE","GT","LE","LT" or None
    evr: Optional[EVR]

@dataclass(frozen=True)
class Requirement:
    name: str
    flags: Optional[str]
    evr: Optional[EVR]

@dataclass
class RepoPkg:
    repo_name: str
    repo_base_url: str
    purl_namespace: str
    purl_distro: str
    name: str
    arch: str
    evr: EVR
    summary: str
    description: str
    license: str
    url: str
    vendor: str
    group: str
    location_href: str
    provides: List[Capability]
    requires: List[Requirement]

    @property
    def key(self) -> Tuple[str, str, int, str, str]:
        return (self.name, self.arch, self.evr.epoch, self.evr.ver, self.evr.rel)


# ----------------------------
# Helpers
# ----------------------------

REPO_NS = {"repo": "http://linux.duke.edu/metadata/repo"}
COMMON_NS = {"c": "http://linux.duke.edu/metadata/common"}
RPM_NS = {"rpm": "http://linux.duke.edu/metadata/rpm"}
FILELISTS_NS = {"f": "http://linux.duke.edu/metadata/filelists"}


def req_satisfied_by_pkg(pkg: RepoPkg, req: Requirement) -> bool:
    for cap in pkg.provides:
        if cap.name != req.name:
            continue
        if req.flags is None:
            return True
        if req.evr is None or cap.evr is None:
            continue
        if satisfies_flags(cap.evr, req.evr, req.flags):
            return True
    return False


def find_satisfier_in_selected(selected: Dict[Tuple[str, str, int, str, str], RepoPkg], req: Requirement) -> Optional[RepoPkg]:
    # Prefer an already-selected package that satisfies the requirement
    for p in selected.values():
        if req_satisfied_by_pkg(p, req):
            return p
    return None


def now_iso8601_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_arch_compatible(arch: str) -> bool:
    if arch == TARGET_ARCH:
        return True
    return ALLOW_NOARCH and arch == "noarch"


def url_escape(s: str) -> str:
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


def build_rpm_purl(pkg: RepoPkg) -> str:
    ns = (PURL_NAMESPACE or "").strip().lower()
    nm = pkg.name.strip().lower()
    ver = f"{pkg.evr.ver}-{pkg.evr.rel}"

    qualifiers = [("arch", pkg.arch)]
    if pkg.evr.epoch != 0:
        qualifiers.append(("epoch", str(pkg.evr.epoch)))
    if PURL_DISTRO:
        qualifiers.append(("distro", PURL_DISTRO))

    q = "&".join(f"{k}={url_escape(v)}" for k, v in sorted(qualifiers, key=lambda x: x[0]))
    if ns:
        return f"pkg:rpm/{ns}/{nm}@{url_escape(ver)}?{q}"
    return f"pkg:rpm/{nm}@{url_escape(ver)}?{q}"


def rpm_style_version(evr: EVR) -> str:
    if evr.epoch != 0:
        return f"{evr.epoch}:{evr.ver}-{evr.rel}"
    return f"{evr.ver}-{evr.rel}"


def path_to_file_uri(p: Path) -> str:
    return p.resolve().as_uri()


def open_compressed_xml(path: Path) -> bytes:
    suffix = path.suffix.lower()
    data = path.read_bytes()
    if suffix == ".gz":
        return gzip.decompress(data)
    if suffix == ".bz2":
        return bz2.decompress(data)
    if suffix in (".xz", ".lzma"):
        return lzma.decompress(data)
    if suffix == ".xml":
        return data
    raise RuntimeError(f"Unsupported metadata compression: {path.name}")


def find_repomd_paths(repo_root: Path) -> Tuple[Path, Path, Optional[Path]]:
    repomd = repo_root / "repodata" / "repomd.xml"
    if not repomd.exists():
        raise FileNotFoundError(f"Missing repomd.xml: {repomd}")

    tree = ET.parse(str(repomd))
    root = tree.getroot()

    primary_href = None
    filelists_href = None

    for data in root.findall("repo:data", REPO_NS):
        typ = data.get("type")
        loc = data.find("repo:location", REPO_NS)
        if loc is None:
            continue
        href = loc.get("href")
        if not href:
            continue
        if typ == "primary":
            primary_href = href
        elif typ == "filelists":
            filelists_href = href

    if not primary_href:
        raise RuntimeError("repomd.xml did not contain a 'primary' entry.")

    primary_path = repo_root / primary_href
    if not primary_path.exists():
        raise FileNotFoundError(f"Primary metadata not found: {primary_path}")

    filelists_path = None
    if ENABLE_FILELISTS_INDEX and filelists_href:
        fp = repo_root / filelists_href
        if fp.exists():
            filelists_path = fp
        else:
            print(f"[warn] filelists enabled but not found: {fp}")

    return repomd, primary_path, filelists_path


def parse_cap_entry(ent: ET.Element) -> Capability:
    name = ent.get("name") or ""
    flags = ent.get("flags")
    epoch = ent.get("epoch")
    ver = ent.get("ver")
    rel = ent.get("rel")

    if flags and ver is not None:
        evr = EVR(int(epoch or "0"), ver or "", rel or "")
        return Capability(name=name, flags=flags, evr=evr)
    return Capability(name=name, flags=None, evr=None)


def parse_req_entry(ent: ET.Element) -> Requirement:
    name = ent.get("name") or ""
    flags = ent.get("flags")
    epoch = ent.get("epoch")
    ver = ent.get("ver")
    rel = ent.get("rel")

    if flags and ver is not None:
        evr = EVR(int(epoch or "0"), ver or "", rel or "")
        return Requirement(name=name, flags=flags, evr=evr)
    return Requirement(name=name, flags=None, evr=None)


# ----------------------------
# Repo index (from repodata)
# ----------------------------

class RepoIndex:
    def __init__(self) -> None:
        self.by_exact: Dict[Tuple[str, str, int, str, str], RepoPkg] = {}
        self.by_name_arch: Dict[Tuple[str, str], List[RepoPkg]] = {}
        self.provides_index: Dict[str, List[Tuple[Tuple[str, str, int, str, str], Capability]]] = {}
        self.file_index: Dict[str, Tuple[str, str, int, str, str]] = {}

    def add_package(self, pkg: RepoPkg) -> None:
        self.by_exact[pkg.key] = pkg
        self.by_name_arch.setdefault((pkg.name, pkg.arch), []).append(pkg)
        for cap in pkg.provides:
            self.provides_index.setdefault(cap.name, []).append((pkg.key, cap))

    def finalize(self) -> None:
        # Sort packages for "latest" selection (epoch desc, then ver/rel as strings; ok for PGDG minor)
        # If you need exact RPM ordering, we can swap this to rpmvercmp logic later.
        for k, lst in self.by_name_arch.items():
            lst.sort(key=lambda p: (p.evr.epoch, p.evr.ver, p.evr.rel), reverse=True)
        for cap, provs in self.provides_index.items():
            provs.sort(
                key=lambda item: (
                    self.by_exact[item[0]].evr.epoch,
                    self.by_exact[item[0]].evr.ver,
                    self.by_exact[item[0]].evr.rel,
                ),
                reverse=True
            )

    def load_from_repodata(self, repo_root: Path) -> Tuple[Path, Optional[Path]]:
        _, primary_path, filelists_path = find_repomd_paths(repo_root)
        print(f"[info] Using primary metadata: {primary_path}")

        xml_bytes = open_compressed_xml(primary_path)
        parser = ET.XMLPullParser(events=("end",))
        parser.feed(xml_bytes)

        count = 0
        for event, elem in parser.read_events():
            if elem.tag == f"{{{COMMON_NS['c']}}}package":
                name = (elem.findtext("c:name", default="", namespaces=COMMON_NS) or "").strip()
                arch = (elem.findtext("c:arch", default="", namespaces=COMMON_NS) or "").strip()
                if not name or not arch or not is_arch_compatible(arch):
                    elem.clear()
                    continue

                v = elem.find("c:version", COMMON_NS)
                epoch = int(v.get("epoch", "0") if v is not None else "0")
                ver = v.get("ver", "") if v is not None else ""
                rel = v.get("rel", "") if v is not None else ""
                evr = EVR(epoch, ver, rel)

                summary = (elem.findtext("c:summary", default="", namespaces=COMMON_NS) or "").strip()
                description = (elem.findtext("c:description", default="", namespaces=COMMON_NS) or "").strip()
                url = (elem.findtext("c:url", default="", namespaces=COMMON_NS) or "").strip()
                loc = elem.find("c:location", COMMON_NS)
                href = loc.get("href", "") if loc is not None else ""

                fmt = elem.find("c:format", COMMON_NS)
                license_s = vendor = group = ""
                provides: List[Capability] = []
                requires: List[Requirement] = []

                if fmt is not None:
                    license_s = (fmt.findtext("rpm:license", default="", namespaces=RPM_NS) or "").strip()
                    vendor = (fmt.findtext("rpm:vendor", default="", namespaces=RPM_NS) or "").strip()
                    group = (fmt.findtext("rpm:group", default="", namespaces=RPM_NS) or "").strip()

                    provs = fmt.find("rpm:provides", RPM_NS)
                    if provs is not None:
                        for ent in provs.findall("rpm:entry", RPM_NS):
                            provides.append(parse_cap_entry(ent))

                    reqs = fmt.find("rpm:requires", RPM_NS)
                    if reqs is not None:
                        for ent in reqs.findall("rpm:entry", RPM_NS):
                            r = parse_req_entry(ent)
                            if r.name.startswith("rpmlib("):
                                continue
                            requires.append(r)

                pkg = RepoPkg(
                    name=name,
                    arch=arch,
                    evr=evr,
                    summary=summary,
                    description=description,
                    license=license_s,
                    url=url,
                    vendor=vendor,
                    group=group,
                    location_href=href,
                    provides=provides,
                    requires=requires,
                )

                self.add_package(pkg)
                count += 1
                elem.clear()

        print(f"[info] Indexed {count} packages from primary metadata.")

        # Optional filelists parse
        if ENABLE_FILELISTS_INDEX and filelists_path is not None:
            print(f"[info] Parsing filelists metadata: {filelists_path}")
            xml_bytes2 = open_compressed_xml(filelists_path)
            parser2 = ET.XMLPullParser(events=("end",))
            parser2.feed(xml_bytes2)

            file_pkg_count = 0
            for event, elem in parser2.read_events():
                if elem.tag == f"{{{FILELISTS_NS['f']}}}package":
                    name = elem.get("name", "")
                    arch = elem.get("arch", "")
                    if not name or not arch or not is_arch_compatible(arch):
                        elem.clear()
                        continue

                    v = elem.find("f:version", FILELISTS_NS)
                    epoch = int(v.get("epoch", "0") if v is not None else "0")
                    ver = v.get("ver", "") if v is not None else ""
                    rel = v.get("rel", "") if v is not None else ""
                    key = (name, arch, epoch, ver, rel)
                    if key not in self.by_exact:
                        elem.clear()
                        continue

                    for f in elem.findall("f:file", FILELISTS_NS):
                        fp = (f.text or "").strip()
                        if fp.startswith("/"):
                            self.file_index.setdefault(fp, key)

                    file_pkg_count += 1
                    elem.clear()

            print(f"[info] Filelists parsed for {file_pkg_count} packages.")

        self.finalize()
        return primary_path, filelists_path


# ----------------------------
# Selecting top-level packages
# ----------------------------

def read_top_level_entries(path: Path) -> List[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()

    if suffix == ".spec":
        name_re = re.compile(r"^\s*Name\s*:\s*(\S+)\s*$", re.IGNORECASE)
        pkg_re = re.compile(r"^\s*%package\s+(.*)$", re.IGNORECASE)
        names: List[str] = []
        for line in text.splitlines():
            m = name_re.match(line)
            if m:
                names.append(m.group(1).strip())
                break
        for line in text.splitlines():
            m = pkg_re.match(line)
            if not m:
                continue
            rest = m.group(1).strip()
            toks = rest.split()
            if len(toks) >= 2 and toks[0] == "-n":
                names.append(toks[1])
            elif toks:
                names.append(toks[0])
        out, seen = [], set()
        for n in names:
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out

    entries: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        entries.append(line)
    return entries


def parse_entry(entry: str) -> Dict[str, str]:
    e = entry.strip()
    if e.lower().endswith(".rpm"):
        e = e[:-4]

    m = re.match(r"^(?P<base>.+)\.(?P<arch>[^.]+)$", e)
    if m and "-" in m.group("base"):
        base = m.group("base")
        arch = m.group("arch")
        toks = base.split("-")
        if len(toks) >= 3:
            name = "-".join(toks[:-2])
            ver = toks[-2]
            rel = toks[-1]
            return {"kind": "filename", "name": name, "ver": ver, "rel": rel, "arch": arch}

    if "." in e and not e.startswith("/"):
        name, arch = e.split(".", 1)
        if arch:
            return {"kind": "name_arch", "name": name, "arch": arch}

    return {"kind": "name", "name": e}


def pick_top_level(idx: RepoIndex, entry: str) -> RepoPkg:
    info = parse_entry(entry)
    kind = info["kind"]

    if kind == "filename":
        name, ver, rel, arch = info["name"], info["ver"], info["rel"], info["arch"]
        if not is_arch_compatible(arch):
            raise RuntimeError(f"Top-level entry arch '{arch}' not compatible with TARGET_ARCH='{TARGET_ARCH}'.")
        candidates = [p for p in idx.by_name_arch.get((name, arch), []) if p.evr.ver == ver and p.evr.rel == rel]
        if not candidates:
            raise RuntimeError(f"Top-level package not found in repodata: {entry}")
        candidates.sort(key=lambda p: p.evr.epoch, reverse=True)
        return candidates[0]

    if kind == "name_arch":
        name, arch = info["name"], info["arch"]
        if not is_arch_compatible(arch):
            raise RuntimeError(f"Top-level entry arch '{arch}' not compatible with TARGET_ARCH='{TARGET_ARCH}'.")
        lst = idx.by_name_arch.get((name, arch), [])
        if not lst:
            raise RuntimeError(f"Top-level package not found in repodata: {name}.{arch}")
        return lst[0]

    name = info["name"]
    lst = idx.by_name_arch.get((name, TARGET_ARCH), [])
    if lst:
        return lst[0]
    if ALLOW_NOARCH:
        lst2 = idx.by_name_arch.get((name, "noarch"), [])
        if lst2:
            return lst2[0]
    raise RuntimeError(f"Top-level package not found in repodata: {name}")


# ----------------------------
# Dependency resolution via repodata
# ----------------------------

def satisfies_flags(provider: EVR, required: EVR, flags: str) -> bool:
    # NOTE: For PGDG minor versions this simple compare is generally OK, but
    # if you need perfect RPM ordering, we can swap in a full rpmvercmp implementation.
    def cmp(a: EVR, b: EVR) -> int:
        if a.epoch != b.epoch:
            return 1 if a.epoch > b.epoch else -1
        if a.ver != b.ver:
            return 1 if a.ver > b.ver else -1
        if a.rel != b.rel:
            return 1 if a.rel > b.rel else -1
        return 0

    c = cmp(provider, required)
    if flags == "EQ":
        return c == 0
    if flags == "GE":
        return c >= 0
    if flags == "GT":
        return c > 0
    if flags == "LE":
        return c <= 0
    if flags == "LT":
        return c < 0
    return False


def pick_provider(idx: RepoIndex, req: Requirement) -> Optional[RepoPkg]:
    # file requires if filelists enabled
    if req.name.startswith("/") and ENABLE_FILELISTS_INDEX:
        key = idx.file_index.get(req.name)
        if key:
            return idx.by_exact.get(key)

    provs = idx.provides_index.get(req.name, [])
    if not provs:
        return None

    for pkg_key, cap in provs:
        pkg = idx.by_exact[pkg_key]
        if not is_arch_compatible(pkg.arch):
            continue
        if req.flags is None:
            return pkg
        if req.evr is None or cap.evr is None:
            continue
        if satisfies_flags(cap.evr, req.evr, req.flags):
            return pkg
    return None


def resolve_closure(
    idx: RepoIndex,
    top_level: List[RepoPkg],
) -> Tuple[List[RepoPkg], Dict[str, Set[str]], List[str], List[str]]:
    """
    Resolve full dependency closure using local repodata indexes.

    Returns:
      - all selected packages (top-level + child deps)
      - edges: pkg_ref -> set(dep_ref)
      - top_level_refs: list of refs for the top-level packages
      - missing requirements: list of strings describing unresolved requirements

    Key behavior:
      - Enforces one version per (name, arch). If a different version is pulled, raises RuntimeError.
      - When satisfying a requirement, prefers an already-selected package that satisfies it
        (prevents unintentionally upgrading pinned top-level packages).
    """
    selected_by_key: Dict[Tuple[str, str, int, str, str], RepoPkg] = {}
    selected_by_name_arch: Dict[Tuple[str, str], RepoPkg] = {}
    edges: Dict[str, Set[str]] = {}
    missing: List[str] = []

    def req_satisfied_by_pkg(pkg: RepoPkg, req: Requirement) -> bool:
        for cap in pkg.provides:
            if cap.name != req.name:
                continue
            if req.flags is None:
                return True
            if req.evr is None or cap.evr is None:
                continue
            if satisfies_flags(cap.evr, req.evr, req.flags):
                return True
        return False

    def find_satisfier_in_selected(req: Requirement) -> Optional[RepoPkg]:
        # Prefer any already selected package that satisfies the requirement
        # (This avoids pulling a newer version from the repo when a pinned one already works.)
        for p in selected_by_key.values():
            if req_satisfied_by_pkg(p, req):
                return p
        return None

    def add_pkg(pkg: RepoPkg) -> bool:
        """
        Add pkg if not already selected.
        Returns True if newly added, False if already present.
        Raises if it would introduce a second version of same (name, arch).
        """
        na = (pkg.name, pkg.arch)

        if na in selected_by_name_arch:
            existing = selected_by_name_arch[na]
            if existing.key != pkg.key:
                raise RuntimeError(
                    "Incompatible set: two versions for same name+arch.\n"
                    f"  Existing: {existing.name}-{rpm_style_version(existing.evr)}.{existing.arch}\n"
                    f"  New:      {pkg.name}-{rpm_style_version(pkg.evr)}.{pkg.arch}"
                )
            return False

        selected_by_key[pkg.key] = pkg
        selected_by_name_arch[na] = pkg
        edges.setdefault(build_rpm_purl(pkg), set())
        return True

    # Seed with top-level packages
    to_process: List[RepoPkg] = []
    for p in top_level:
        if add_pkg(p):
            to_process.append(p)
        else:
            # still ensure top-level is processed if it was already present (unlikely but safe)
            to_process.append(p)

    top_level_refs = [build_rpm_purl(p) for p in top_level]

    processed: Set[Tuple[str, str, int, str, str]] = set()

    # BFS over dependency graph
    while to_process:
        pkg = to_process.pop(0)
        if pkg.key in processed:
            continue
        processed.add(pkg.key)

        pkg_ref = build_rpm_purl(pkg)
        edges.setdefault(pkg_ref, set())

        for req in pkg.requires:
            # 1) Prefer already-selected satisfier (prevents version upgrades)
            satisfier = find_satisfier_in_selected(req)
            if satisfier is not None:
                edges[pkg_ref].add(build_rpm_purl(satisfier))
                continue

            # 2) Otherwise, pick a provider from the repo metadata
            provider = pick_provider(idx, req)
            if provider is None:
                missing.append(
                    f"{pkg.name}-{rpm_style_version(pkg.evr)}.{pkg.arch} requires {req.name}"
                    + (
                        f" ({req.flags} {req.evr.epoch}:{req.evr.ver}-{req.evr.rel})"
                        if req.flags and req.evr
                        else ""
                    )
                )
                continue

            edges[pkg_ref].add(build_rpm_purl(provider))

            # 3) Add provider and process if newly added
            newly_added = add_pkg(provider)
            if newly_added:
                to_process.append(provider)

    all_pkgs = list(selected_by_key.values())
    all_pkgs.sort(key=lambda p: (p.name, p.arch, p.evr.epoch, p.evr.ver, p.evr.rel))
    return all_pkgs, edges, top_level_refs, missing


# ----------------------------
# Download RPMs using location_href from repodata
# ----------------------------

def http_download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)


def ensure_rpm_downloaded(pkg: RepoPkg) -> Optional[Path]:
    """
    Download the RPM referenced by pkg.location_href into Config.rpm_cache_dir.
    Returns local path if downloaded/present; otherwise None.
    """
    href = (pkg.location_href or "").strip()
    if not href:
        return None

    # Preserve repo-relative path inside cache so you can later form a local repo layout if desired.
    dest = Config.rpm_cache_dir / Path(href.replace("/", os.sep))
    if dest.exists():
        return dest

    url = REPO_BASE_URL.rstrip("/") + "/" + href.lstrip("/")
    print(f"[dl] {pkg.name}: {url}")
    http_download(url, dest)
    return dest


# ----------------------------
# SBOM generation
# ----------------------------

def pkg_to_component(pkg: RepoPkg) -> Dict[str, object]:
    purl = build_rpm_purl(pkg)

    licenses: List[object] = []
    if pkg.license:
        licenses.append({"license": {"name": pkg.license}})

    external_refs: List[Dict[str, str]] = []
    if pkg.url:
        external_refs.append({"type": "website", "url": pkg.url})

    # distribution: prefer local file:// if downloaded, else remote URL
    if pkg.location_href:
        local_path = Config.rpm_cache_dir / Path(pkg.location_href.replace("/", os.sep))
        if local_path.exists():
            external_refs.append({"type": "distribution", "url": path_to_file_uri(local_path)})
        else:
            external_refs.append({"type": "distribution", "url": REPO_BASE_URL.rstrip("/") + "/" + pkg.location_href.lstrip("/")})

    desc = pkg.description or pkg.summary or ""
    group = pkg.vendor or pkg.group or ""

    return {
        "type": "library",
        "name": pkg.name,
        "group": group,
        "version": rpm_style_version(pkg.evr),
        "purl": purl,
        "bom-ref": purl,
        "description": desc,
        "licenses": licenses,
        "externalReferences": external_refs,
    }


def build_sbom(all_pkgs: List[RepoPkg], edges: Dict[str, Set[str]], top_level_refs: List[str]) -> Dict[str, object]:
    components = [pkg_to_component(p) for p in all_pkgs]

    deps: List[Dict[str, object]] = []
    root_ref = SBOM_ROOT_COMPONENT.get("bom-ref", "sbom-root")
    deps.append({"ref": root_ref, "dependsOn": sorted(set(top_level_refs))})

    for p in all_pkgs:
        ref = build_rpm_purl(p)
        deps.append({"ref": ref, "dependsOn": sorted(edges.get(ref, set()))})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SBOM_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": SBOM_VERSION,
        "metadata": {
            "timestamp": now_iso8601_utc(),
            "component": SBOM_ROOT_COMPONENT,
        },
        "components": components,
        "dependencies": deps,
    }


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    Config.rpm_txt_file_path = Path(Config.sbom_input_dir, Config.rpm_txt_file_name)
    Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
    Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")
    Config.rpms_folder_path = Path(Config.sbom_input_dir, Config.rpms_folder_name)
    Config.rpm_local_repo = Path(Config.sbom_input_dir, "rpm_repos/pgdg18-rhel9-x86_64")
    Config.rpm_cache_dir = Path(Config.cache_dir, "rpm_cache")

    repomd = Path(Config.rpm_local_repo, "repodata", "repomd.xml")
    #repomd = Config.rpm_local_repo / "repodata" / "repomd.xml"
    if not repomd.exists():
        raise RuntimeError(
            f"repodata not found. Expected: {repomd}\n"
            "Point Config.rpm_local_repo at the folder created by your repodata bootstrap script."
        )

    entries = read_top_level_entries(Config.rpm_txt_file_path)
    if not entries:
        raise RuntimeError(f"No top-level entries found in {Config.rpm_txt_file_path}")

    idx = RepoIndex()
    idx.load_from_repodata(Config.rpm_local_repo)

    top_level = [pick_top_level(idx, e) for e in entries]
    all_pkgs, edges, top_level_refs, missing = resolve_closure(idx, top_level)

    if missing:
        msg = "[warn] Some requirements could not be satisfied by this repo's repodata:\n  " + "\n  ".join(missing)
        if STRICT_RESOLUTION:
            raise RuntimeError(msg)
        print(msg)

    if DOWNLOAD_RESOLVED_RPMS:
        Config.rpm_cache_dir.mkdir(parents=True, exist_ok=True)
        for p in all_pkgs:
            try:
                ensure_rpm_downloaded(p)
            except Exception as e:
                # Not fatal for SBOM; you still have metadata.
                print(f"[warn] failed to download {p.name}: {e}")

    sbom = build_sbom(all_pkgs, edges, top_level_refs)
    Config.sbom_output_file_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    print(f"[ok] Wrote SBOM: {Config.sbom_output_file_path.resolve()}")
    print(f"[ok] Components (top-level + deps): {len(sbom['components'])}")
    print(f"[ok] Top-level matched: {len(set(top_level_refs))}")
    if DOWNLOAD_RESOLVED_RPMS:
        print(f"[ok] RPM cache dir: {Config.rpm_cache_dir.resolve()}")


if __name__ == "__main__":
    main()