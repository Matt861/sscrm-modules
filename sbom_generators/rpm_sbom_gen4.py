#!/usr/bin/env python3
"""
Windows-only RPM SBOM generator (CycloneDX-shaped JSON) with MULTI-REPO resolution via local repodata/

What this supports:
- Reads top-level packages from .txt (recommended) OR .spec
- Uses LOCAL repodata/ (primary.xml.* and optionally filelists.xml.*) for dependency resolution
- Resolves full dependency closure across MULTIPLE repos (e.g., PGDG + UBI9 BaseOS/AppStream/CRB)
- Prefers already-selected packages when satisfying a requirement (prevents accidental upgrades)
- Enforces one version per (name, arch) across the resolved set
- (Optional) downloads the resolved RPM payloads using each package's location href + repo base_url

Prereqs (pure Python; Windows compatible):
  pip install rpm-vercmp

Inputs you must already have (downloaded by your repodata bootstrap script):
  <local_dir>\repodata\repomd.xml
  <local_dir>\repodata\<hash>-primary.xml.gz  (and filelists if enabled)

No command-line args: edit CONFIG section below.
"""

from configuration import Configuration as Config
import bz2
import gzip
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

# Input list of top-level packages
# - .txt: each line can be an RPM filename, name.arch, or name
# - .spec: extracts Name: and %package subpackages
#Config.rpm_txt_file_path = Path(r".\top_level_rpms.txt")

# Multi-repo configuration:
# IMPORTANT: local_dir must already contain repodata/ downloaded by your bootstrap script.

# Output SBOM JSON
#Config.sbom_output_file_path = Path(r".\sbom.rpm.cdx.json")

# Where to store downloaded RPM payloads (if enabled)
#Config.rpm_cache_dir = Path(r".\rpm_cache")

# Arch policy
TARGET_ARCH = "x86_64"
ALLOW_NOARCH = True

# Enable filelists metadata parsing so file-path requirements like /bin/sh can resolve.
# NOTE: filelists can be large.
ENABLE_FILELISTS_INDEX = True

# If True, download RPM files for all resolved packages (top-level + deps)
DOWNLOAD_RESOLVED_RPMS = True

# If True, fail if ANY requirement cannot be satisfied by the configured repos.
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
    "description": "SBOM generated on Windows from local repodata/ across multiple RPM repositories.",
}

# Optional: proxy support (hard-code or leave None)
# PROXIES = {"https": "http://proxy.company.local:8080"}
PROXIES: Optional[Dict[str, str]] = None
USER_AGENT = "rpm-sbom-generator/1.0"


# ----------------------------
# Dependencies (pure Python)
# ----------------------------

try:
    import rpm_vercmp  # pip install rpm-vercmp
except Exception as e:
    raise RuntimeError(
        "Missing dependency: rpm-vercmp. Install with: pip install rpm-vercmp\n"
        f"Import error: {e}"
    )


# ----------------------------
# Namespaces used in repodata
# ----------------------------

REPO_NS = {"repo": "http://linux.duke.edu/metadata/repo"}
COMMON_NS = {"c": "http://linux.duke.edu/metadata/common"}
RPM_NS = {"rpm": "http://linux.duke.edu/metadata/rpm"}
FILELISTS_NS = {"f": "http://linux.duke.edu/metadata/filelists"}


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


# Unique key for a package entry in our index (include repo_name to avoid collisions)
PkgId = Tuple[str, str, str, int, str, str]  # (repo_name, name, arch, epoch, ver, rel)


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

    location_href: str  # repo-relative path to rpm
    provides: List[Capability]
    requires: List[Requirement]

    def pkg_id(self) -> PkgId:
        return (self.repo_name, self.name, self.arch, self.evr.epoch, self.evr.ver, self.evr.rel)

    def nevra(self) -> Tuple[str, str, int, str, str]:
        return (self.name, self.arch, self.evr.epoch, self.evr.ver, self.evr.rel)


# ----------------------------
# Utility functions
# ----------------------------

RICH_OP_MAP = {
    "=": "EQ",
    ">=": "GE",
    ">": "GT",
    "<=": "LE",
    "<": "LT",
}

def _strip_outer_parens(s: str) -> str:
    s = s.strip()
    if s.startswith("(") and s.endswith(")"):
        return s[1:-1].strip()
    return s

def _parse_evr_string(v: str) -> EVR:
    """
    Accepts:  '2.34-231.el9_7.10' or '0:1.4.0-' or '1:2.0-3'
    Returns:  EVR(epoch, ver, rel)
    """
    v = v.strip()
    epoch = 0
    if ":" in v:
        ep, rest = v.split(":", 1)
        if ep.isdigit():
            epoch = int(ep)
            v = rest

    # Some rpm constraints may end with '-' (meaning no release in the expression)
    # e.g. '1.4.0-'
    if v.endswith("-"):
        v = v[:-1]

    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ""

    return EVR(epoch=epoch, ver=ver, rel=rel)

def parse_simple_dep_string(expr: str) -> Requirement:
    """
    Parses 'NAME', or 'NAME <op> EVRSTRING'
    NAME may contain parentheses, e.g. 'glibc-gconv-extra(x86-64)'.
    """
    expr = expr.strip()

    # Find an operator with surrounding whitespace (typical in rich deps)
    for sym in (">=", "<=", "=", ">", "<"):
        token = f" {sym} "
        if token in expr:
            name, ver_s = expr.split(token, 1)
            name = name.strip()
            ver_s = ver_s.strip()
            flags = RICH_OP_MAP[sym]
            evr = _parse_evr_string(ver_s)
            return Requirement(name=name, flags=flags, evr=evr)

    return Requirement(name=expr, flags=None, evr=None)

def try_parse_rich_bool(expr: str) -> Optional[dict]:
    """
    Minimal parser for common RPM rich deps:
      (A if B)
      (A if B else C)
      (A unless B)
      (A unless B else C)

    Returns a dict like:
      {"op":"if", "a": "...", "b":"..."}
    or None if not recognized.
    """
    inner = _strip_outer_parens(expr)
    # Quick filter: avoid doing work on normal names
    if " if " in inner:
        left, rest = inner.split(" if ", 1)
        if " else " in rest:
            cond, else_part = rest.split(" else ", 1)
            return {"op": "ifelse", "a": left.strip(), "b": cond.strip(), "c": else_part.strip()}
        return {"op": "if", "a": left.strip(), "b": rest.strip()}

    if " unless " in inner:
        left, rest = inner.split(" unless ", 1)
        if " else " in rest:
            cond, else_part = rest.split(" else ", 1)
            return {"op": "unlesselse", "a": left.strip(), "b": cond.strip(), "c": else_part.strip()}
        return {"op": "unless", "a": left.strip(), "b": rest.strip()}

    return None


def _build_opener() -> urllib.request.OpenerDirector:
    handlers: List[urllib.request.BaseHandler] = []
    if PROXIES:
        handlers.append(urllib.request.ProxyHandler(PROXIES))
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener


def http_download(opener: urllib.request.OpenerDirector, url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with opener.open(url) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)


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
    ns = (pkg.purl_namespace or "").strip().lower()
    nm = pkg.name.strip().lower()
    ver = f"{pkg.evr.ver}-{pkg.evr.rel}"

    qualifiers = [("arch", pkg.arch)]
    if pkg.evr.epoch != 0:
        qualifiers.append(("epoch", str(pkg.evr.epoch)))
    if pkg.purl_distro:
        qualifiers.append(("distro", pkg.purl_distro))

    q = "&".join(f"{k}={url_escape(v)}" for k, v in sorted(qualifiers, key=lambda x: x[0]))
    if ns:
        return f"pkg:rpm/{ns}/{nm}@{url_escape(ver)}?{q}"
    return f"pkg:rpm/{nm}@{url_escape(ver)}?{q}"


def rpm_style_version(evr: EVR) -> str:
    if evr.epoch != 0:
        return f"{evr.epoch}:{evr.ver}-{evr.rel}"
    return f"{evr.ver}-{evr.rel}"


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


def compare_evr(a: EVR, b: EVR) -> int:
    if a.epoch != b.epoch:
        return 1 if a.epoch > b.epoch else -1
    c = rpm_vercmp.vercmp(a.ver or "", b.ver or "")
    if c != 0:
        return c
    return rpm_vercmp.vercmp(a.rel or "", b.rel or "")


def satisfies_flags(provider: EVR, required: EVR, flags: str) -> bool:
    c = compare_evr(provider, required)
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


def parse_cap_entry(ent: ET.Element) -> Capability:
    name = (ent.get("name") or "").strip()
    flags = ent.get("flags")
    epoch = ent.get("epoch")
    ver = ent.get("ver")
    rel = ent.get("rel")

    if flags and ver is not None:
        evr = EVR(int(epoch or "0"), ver or "", rel or "")
        return Capability(name=name, flags=flags, evr=evr)
    return Capability(name=name, flags=None, evr=None)


def parse_req_entry(ent: ET.Element) -> Requirement:
    name = (ent.get("name") or "").strip()
    flags = ent.get("flags")
    epoch = ent.get("epoch")
    ver = ent.get("ver")
    rel = ent.get("rel")

    if flags and ver is not None:
        evr = EVR(int(epoch or "0"), ver or "", rel or "")
        return Requirement(name=name, flags=flags, evr=evr)
    return Requirement(name=name, flags=None, evr=None)


# ----------------------------
# Repo index across multiple repos
# ----------------------------

class RepoIndex:
    def __init__(self) -> None:
        self.by_id: Dict[PkgId, RepoPkg] = {}
        self.by_name_arch: Dict[Tuple[str, str], List[PkgId]] = {}
        self.provides_index: Dict[str, List[Tuple[PkgId, Capability]]] = {}
        self.file_index: Dict[str, PkgId] = {}  # file path -> best pkg_id

    def add_package(self, pkg: RepoPkg) -> None:
        pid = pkg.pkg_id()
        self.by_id[pid] = pkg
        self.by_name_arch.setdefault((pkg.name, pkg.arch), []).append(pid)

        for cap in pkg.provides:
            if cap.name:
                self.provides_index.setdefault(cap.name, []).append((pid, cap))

        # Also ensure the package name itself is a provided capability
        self.provides_index.setdefault(pkg.name, []).append(
            (pid, Capability(name=pkg.name, flags="EQ", evr=pkg.evr))
        )

    def finalize(self) -> None:
        # Sort by_name_arch lists by descending EVR so "latest" is first
        def pid_key(pid: PkgId) -> Tuple[int, str, str]:
            p = self.by_id[pid]
            return (p.evr.epoch, p.evr.ver, p.evr.rel)

        for k, lst in self.by_name_arch.items():
            lst.sort(
                key=lambda pid: (
                    self.by_id[pid].evr.epoch,
                    self.by_id[pid].evr.ver,
                    self.by_id[pid].evr.rel,
                ),
                reverse=True,
            )

        # Sort provides candidates by descending package EVR
        for cap, provs in self.provides_index.items():
            provs.sort(
                key=lambda item: (
                    self.by_id[item[0]].evr.epoch,
                    self.by_id[item[0]].evr.ver,
                    self.by_id[item[0]].evr.rel,
                ),
                reverse=True,
            )

    def load_repo(
        self,
        repo_root: Path,
        repo_name: str,
        repo_base_url: str,
        purl_namespace: str,
        purl_distro: str,
    ) -> None:
        repomd, primary_path, filelists_path = find_repomd_paths(repo_root)
        print(f"[info] Loading repo '{repo_name}' primary metadata: {primary_path}")

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
                            # Ignore internal rpmlib() requirements
                            if r.name.startswith("rpmlib("):
                                continue
                            requires.append(r)

                pkg = RepoPkg(
                    repo_name=repo_name,
                    repo_base_url=repo_base_url,
                    purl_namespace=purl_namespace,
                    purl_distro=purl_distro,
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

        print(f"[info] Repo '{repo_name}': indexed {count} packages from primary metadata.")

        if ENABLE_FILELISTS_INDEX and filelists_path is not None:
            print(f"[info] Repo '{repo_name}': parsing filelists metadata: {filelists_path}")
            xml_bytes2 = open_compressed_xml(filelists_path)
            parser2 = ET.XMLPullParser(events=("end",))
            parser2.feed(xml_bytes2)

            fl_count = 0
            for event, elem in parser2.read_events():
                if elem.tag == f"{{{FILELISTS_NS['f']}}}package":
                    name = (elem.get("name") or "").strip()
                    arch = (elem.get("arch") or "").strip()
                    if not name or not arch or not is_arch_compatible(arch):
                        elem.clear()
                        continue

                    v = elem.find("f:version", FILELISTS_NS)
                    epoch = int(v.get("epoch", "0") if v is not None else "0")
                    ver = v.get("ver", "") if v is not None else ""
                    rel = v.get("rel", "") if v is not None else ""
                    pid: PkgId = (repo_name, name, arch, epoch, ver, rel)

                    if pid not in self.by_id:
                        elem.clear()
                        continue

                    for f in elem.findall("f:file", FILELISTS_NS):
                        fp = (f.text or "").strip()
                        if not fp.startswith("/"):
                            continue

                        # Choose "best" provider for that file path by EVR
                        if fp not in self.file_index:
                            self.file_index[fp] = pid
                        else:
                            existing = self.by_id[self.file_index[fp]]
                            candidate = self.by_id[pid]
                            if compare_evr(candidate.evr, existing.evr) > 0:
                                self.file_index[fp] = pid

                    fl_count += 1
                    elem.clear()

            print(f"[info] Repo '{repo_name}': filelists parsed for {fl_count} packages.")

    # Provider selection helpers

    def pick_top_level_latest(self, name: str, arch: str) -> RepoPkg:
        lst = self.by_name_arch.get((name, arch), [])
        if not lst:
            raise RuntimeError(f"Top-level package not found in repodata: {name}.{arch}")
        return self.by_id[lst[0]]

    def pick_provider(self, req: Requirement) -> Optional[RepoPkg]:
        # File-path requires (e.g. /bin/sh) need filelists index
        if req.name.startswith("/") and ENABLE_FILELISTS_INDEX:
            pid = self.file_index.get(req.name)
            if pid:
                return self.by_id.get(pid)

        candidates = self.provides_index.get(req.name, [])
        if not candidates:
            return None

        for pid, cap in candidates:
            pkg = self.by_id[pid]
            if not is_arch_compatible(pkg.arch):
                continue

            # Unversioned requirement
            if req.flags is None:
                return pkg

            # Versioned requirement: we need req.evr
            if req.evr is None:
                continue

            # Provider EVR:
            # - Use cap.evr if present; else use pkg.evr
            prov_evr = cap.evr or pkg.evr
            if satisfies_flags(prov_evr, req.evr, req.flags):
                return pkg

        return None


# ----------------------------
# Reading top-level entries (.txt / .spec)
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

        out: List[str] = []
        seen: Set[str] = set()
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
    """
    Accepts:
      - filename.rpm  (name-ver-rel.arch.rpm)
      - name-ver-rel.arch
      - name.arch
      - name
    Returns a dict with kind + parsed fields.
    """
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

        # Search across all repos for exact ver+rel (pick highest epoch if multiple)
        matches: List[RepoPkg] = []
        for pid in idx.by_name_arch.get((name, arch), []):
            p = idx.by_id[pid]
            if p.evr.ver == ver and p.evr.rel == rel:
                matches.append(p)

        if not matches:
            raise RuntimeError(f"Top-level package not found in repodata: {entry}")

        matches.sort(key=lambda p: p.evr.epoch, reverse=True)
        return matches[0]

    if kind == "name_arch":
        name, arch = info["name"], info["arch"]
        if not is_arch_compatible(arch):
            raise RuntimeError(f"Top-level entry arch '{arch}' not compatible with TARGET_ARCH='{TARGET_ARCH}'.")
        return idx.pick_top_level_latest(name, arch)

    # kind == "name"
    name = info["name"]
    if idx.by_name_arch.get((name, TARGET_ARCH)):
        return idx.pick_top_level_latest(name, TARGET_ARCH)
    if ALLOW_NOARCH and idx.by_name_arch.get((name, "noarch")):
        return idx.pick_top_level_latest(name, "noarch")
    raise RuntimeError(f"Top-level package not found in repodata: {name}")


# ----------------------------
# Dependency resolution (multi-repo)
# ----------------------------

def resolve_closure(
    idx: RepoIndex,
    top_level: List[RepoPkg],
) -> Tuple[List[RepoPkg], Dict[str, Set[str]], List[str], List[str]]:
    selected_by_id: Dict[PkgId, RepoPkg] = {}
    selected_by_name_arch: Dict[Tuple[str, str], RepoPkg] = {}
    edges: Dict[str, Set[str]] = {}
    missing: List[str] = []

    # Pending boolean deps whose condition isn't known/true yet.
    # Each item: (origin_pkg, origin_ref, required_req, condition_req, else_req_or_none, semantics)
    pending_bool: List[Tuple[RepoPkg, str, Requirement, Requirement, Optional[Requirement], str]] = []

    def req_satisfied_by_pkg(pkg: RepoPkg, req: Requirement) -> bool:
        if req.name.startswith("/") and ENABLE_FILELISTS_INDEX:
            pid = idx.file_index.get(req.name)
            if pid and idx.by_id[pid].nevra() == pkg.nevra():
                return True
            return False

        for cap in pkg.provides:
            if cap.name != req.name:
                continue
            if req.flags is None:
                return True
            if req.evr is None:
                continue
            prov_evr = cap.evr or pkg.evr
            if satisfies_flags(prov_evr, req.evr, req.flags):
                return True

        if req.name == pkg.name:
            if req.flags is None:
                return True
            if req.evr is not None and satisfies_flags(pkg.evr, req.evr, req.flags):
                return True

        return False

    def find_satisfier_in_selected(req: Requirement) -> Optional[RepoPkg]:
        for p in selected_by_id.values():
            if req_satisfied_by_pkg(p, req):
                return p
        return None

    def add_pkg(pkg: RepoPkg) -> bool:
        na = (pkg.name, pkg.arch)
        if na in selected_by_name_arch:
            existing = selected_by_name_arch[na]
            if existing.nevra() != pkg.nevra():
                raise RuntimeError(
                    "Incompatible set: two versions for same name+arch.\n"
                    f"  Existing: {existing.name}-{existing.evr.ver}-{existing.evr.rel}.{existing.arch} (repo={existing.repo_name})\n"
                    f"  New:      {pkg.name}-{pkg.evr.ver}-{pkg.evr.rel}.{pkg.arch} (repo={pkg.repo_name})"
                )
            return False

        selected_by_name_arch[na] = pkg
        selected_by_id[pkg.pkg_id()] = pkg
        edges.setdefault(build_rpm_purl(pkg), set())
        return True

    def record_missing(origin: RepoPkg, req: Requirement) -> None:
        s = (
            f"{origin.name}-{rpm_style_version(origin.evr)}.{origin.arch} requires {req.name}"
            + (
                f" ({req.flags} {req.evr.epoch}:{req.evr.ver}-{req.evr.rel})"
                if req.flags and req.evr
                else ""
            )
        )
        missing.append(s)

    def process_requirement(origin: RepoPkg, origin_ref: str, req: Requirement, to_process: List[RepoPkg]) -> None:
        satisfier = find_satisfier_in_selected(req)
        if satisfier is not None:
            edges[origin_ref].add(build_rpm_purl(satisfier))
            return

        provider = idx.pick_provider(req)
        if provider is None:
            record_missing(origin, req)
            return

        edges[origin_ref].add(build_rpm_purl(provider))
        before = len(selected_by_name_arch)
        add_pkg(provider)
        after = len(selected_by_name_arch)
        if after > before:
            to_process.append(provider)

    def drain_pending(to_process: List[RepoPkg]) -> None:
        """
        Re-evaluate pending boolean deps whenever the selected set grows.
        """
        changed = True
        while changed:
            changed = False
            still_pending: List[Tuple[RepoPkg, str, Requirement, Requirement, Optional[Requirement], str]] = []

            for origin, origin_ref, a_req, cond_req, else_req, op in pending_bool:
                cond_true = find_satisfier_in_selected(cond_req) is not None

                if op == "if":
                    if cond_true:
                        process_requirement(origin, origin_ref, a_req, to_process)
                    # if cond is false, term is satisfied (no action) per RPM semantics
                    changed = changed or cond_true
                    continue

                if op == "ifelse":
                    if cond_true:
                        process_requirement(origin, origin_ref, a_req, to_process)
                    else:
                        assert else_req is not None
                        process_requirement(origin, origin_ref, else_req, to_process)
                    changed = True
                    continue

                if op == "unless":
                    if not cond_true:
                        process_requirement(origin, origin_ref, a_req, to_process)
                        changed = True
                    # if cond is true, term is satisfied
                    continue

                if op == "unlesselse":
                    if not cond_true:
                        process_requirement(origin, origin_ref, a_req, to_process)
                    else:
                        assert else_req is not None
                        process_requirement(origin, origin_ref, else_req, to_process)
                    changed = True
                    continue

                # Unknown op: keep pending (shouldn't happen)
                still_pending.append((origin, origin_ref, a_req, cond_req, else_req, op))

            pending_bool[:] = still_pending

    # Seed
    to_process: List[RepoPkg] = []
    for p in top_level:
        add_pkg(p)
        to_process.append(p)

    top_level_refs = [build_rpm_purl(p) for p in top_level]
    processed: Set[Tuple[str, str, int, str, str]] = set()

    while to_process:
        pkg = to_process.pop(0)
        if pkg.nevra() in processed:
            continue
        processed.add(pkg.nevra())

        pkg_ref = build_rpm_purl(pkg)
        edges.setdefault(pkg_ref, set())

        for req in pkg.requires:
            # Detect and evaluate RPM rich/boolean dependency expressions.
            rich = try_parse_rich_bool(req.name) if (req.flags is None and req.evr is None) else None
            if rich is not None:
                a_req = parse_simple_dep_string(rich["a"])
                cond_req = parse_simple_dep_string(rich["b"])
                else_req = parse_simple_dep_string(rich["c"]) if "c" in rich else None

                # Evaluate now if possible; otherwise queue and re-check when set grows.
                cond_true = find_satisfier_in_selected(cond_req) is not None

                if rich["op"] == "if":
                    if cond_true:
                        process_requirement(pkg, pkg_ref, a_req, to_process)
                    else:
                        # If condition isn't present, RPM semantics consider the term satisfied.
                        # (A if B) is True when B is not installed. :contentReference[oaicite:2]{index=2}
                        pass
                    continue

                if rich["op"] == "ifelse":
                    if cond_true:
                        process_requirement(pkg, pkg_ref, a_req, to_process)
                    else:
                        assert else_req is not None
                        process_requirement(pkg, pkg_ref, else_req, to_process)
                    continue

                if rich["op"] == "unless":
                    if not cond_true:
                        process_requirement(pkg, pkg_ref, a_req, to_process)
                    continue

                if rich["op"] == "unlesselse":
                    if not cond_true:
                        process_requirement(pkg, pkg_ref, a_req, to_process)
                    else:
                        assert else_req is not None
                        process_requirement(pkg, pkg_ref, else_req, to_process)
                    continue

                # Fallback: keep pending if we didn't recognize it
                pending_bool.append((pkg, pkg_ref, a_req, cond_req, else_req, rich["op"]))
                continue

            # Normal dependency
            process_requirement(pkg, pkg_ref, req, to_process)

        # After processing one package, re-check any pending boolean deps that might have become active
        drain_pending(to_process)

    # De-dupe missing lines
    missing_dedup: List[str] = []
    seen_m: Set[str] = set()
    for m in missing:
        if m not in seen_m:
            seen_m.add(m)
            missing_dedup.append(m)

    all_pkgs = list(selected_by_name_arch.values())
    all_pkgs.sort(key=lambda p: (p.name, p.arch, p.evr.epoch, p.evr.ver, p.evr.rel, p.repo_name))
    return all_pkgs, edges, top_level_refs, missing_dedup


# ----------------------------
# Download RPM payloads
# ----------------------------

def ensure_rpm_downloaded(opener: urllib.request.OpenerDirector, pkg: RepoPkg) -> Optional[Path]:
    href = (pkg.location_href or "").strip()
    if not href:
        return None

    dest = Config.rpm_cache_dir / pkg.repo_name / Path(href.replace("/", os.sep))
    if dest.exists():
        return dest

    url = pkg.repo_base_url.rstrip("/") + "/" + href.lstrip("/")
    print(f"[dl] {pkg.repo_name} {pkg.name}: {url}")
    http_download(opener, url, dest)
    return dest


def path_to_file_uri(p: Path) -> str:
    return p.resolve().as_uri()


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

    if pkg.location_href:
        external_refs.append(
            {"type": "distribution", "url": pkg.repo_base_url.rstrip("/") + "/" + pkg.location_href.lstrip("/")}
        )
        # local_path = Config.rpm_cache_dir / pkg.repo_name / Path(pkg.location_href.replace("/", os.sep))
        # if local_path.exists():
        #     external_refs.append({"type": "distribution", "url": path_to_file_uri(local_path)})
        # else:
        #     external_refs.append(
        #         {"type": "distribution", "url": pkg.repo_base_url.rstrip("/") + "/" + pkg.location_href.lstrip("/")}
        #     )

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
    Config.rpm_local_repos_path = Path(Config.sbom_input_dir, "rpm_repos")
    Config.rpm_repos = [
        {
            "name": "pgdg18",
            "local_dir": Path(Config.rpm_local_repos_path, "pgdg18-rhel9-x86_64"),
            "base_url": "https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-9-x86_64/",
            "purl_namespace": "pgdg",
            "purl_distro": "rhel-9",
        },
        # UBI 9 repos (recommended for UBI9-minimal target)
        {
            "name": "ubi9-baseos",
            "local_dir": Path(Config.rpm_local_repos_path, "ubi9-baseos-x86_64"),
            "base_url": "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/",
            "purl_namespace": "ubi",
            "purl_distro": "ubi-9",
        },
        {
            "name": "ubi9-appstream",
            "local_dir": Path(Config.rpm_local_repos_path, "ubi9-appstream-x86_64"),
            "base_url": "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/appstream/os/",
            "purl_namespace": "ubi",
            "purl_distro": "ubi-9",
        },
        # Optional but often useful
        {
            "name": "ubi9-crb",
            "local_dir": Path(Config.rpm_local_repos_path, "ubi9-codeready-builder-x86_64"),
            "base_url": "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/os/",
            "purl_namespace": "ubi",
            "purl_distro": "ubi-9",
        },
    ]
    # Validate local repodata exists for each repo
    for r in Config.rpm_repos:
        repomd = Path(r["local_dir"]) / "repodata" / "repomd.xml"
        if not repomd.exists():
            raise RuntimeError(
                f"repodata not found for repo '{r['name']}'. Expected: {repomd}\n"
                "Run your repodata bootstrap downloader for this repo first."
            )

    entries = read_top_level_entries(Config.rpm_txt_file_path)
    if not entries:
        raise RuntimeError(f"No top-level entries found in {Config.rpm_txt_file_path}")

    # Build combined index
    idx = RepoIndex()
    for r in Config.rpm_repos:
        idx.load_repo(
            repo_root=Path(r["local_dir"]),
            repo_name=r["name"],
            repo_base_url=r["base_url"],
            purl_namespace=r["purl_namespace"],
            purl_distro=r["purl_distro"],
        )
    idx.finalize()

    # Pick top-level packages
    top_level = [pick_top_level(idx, e) for e in entries]

    # Resolve closure
    all_pkgs, edges, top_level_refs, missing = resolve_closure(idx, top_level)

    if missing:
        msg = "[warn] Some requirements could not be satisfied by configured repos:\n  " + "\n  ".join(missing)
        if STRICT_RESOLUTION:
            raise RuntimeError(msg)
        print(msg)

    # Download payloads (optional)
    opener = _build_opener()
    if DOWNLOAD_RESOLVED_RPMS:
        Config.rpm_cache_dir.mkdir(parents=True, exist_ok=True)
        for p in all_pkgs:
            try:
                ensure_rpm_downloaded(opener, p)
            except Exception as e:
                # Not fatal for SBOM: metadata is still valid.
                print(f"[warn] failed to download {p.repo_name}:{p.name}: {e}")

    # Build + write SBOM
    sbom = build_sbom(all_pkgs, edges, top_level_refs)
    Config.sbom_output_file_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    print(f"[ok] Wrote SBOM: {Config.sbom_output_file_path.resolve()}")
    print(f"[ok] Components: {len(sbom['components'])}")
    print(f"[ok] Top-level matched: {len(set(top_level_refs))}")
    if DOWNLOAD_RESOLVED_RPMS:
        print(f"[ok] RPM cache dir: {Config.rpm_cache_dir.resolve()}")


if __name__ == "__main__":
    main()