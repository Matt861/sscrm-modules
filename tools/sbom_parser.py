#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional, Iterable

from configuration import Configuration as Config
from models.component import Component, ComponentStore
from utils import normalize_github_url


# --- GitHub URL matching / normalization ---

# Allowed input formats:
#   https://github.com/owner/repo
#   http://github.com/owner/repo
#   https://github.com/owner/repo.git
#   git@github.com:owner/repo.git
#
# Output format:
#   https://github.com/owner/repo


# --- CycloneDX JSON helpers ---

def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    return str(v).strip() or None


def _component_group_like(c: dict[str, Any]) -> Optional[str]:
    # Maven SBOMs often use "group"; some producers use "namespace"
    return _safe_str(c.get("group")) or _safe_str(c.get("namespace"))


def _bom_ref(c: dict[str, Any]) -> Optional[str]:
    # CycloneDX JSON commonly uses "bom-ref"; be tolerant of "bomRef"
    return _safe_str(c.get("bom-ref")) or _safe_str(c.get("bomRef"))


def extract_urls(component: dict[str, Any]) -> tuple[list[str], list[str]]:
    vcs_urls: list[str] = []
    other_urls: list[str] = []

    ext_refs = component.get("externalReferences")
    if not isinstance(ext_refs, list):
        return vcs_urls, other_urls

    for ref in ext_refs:
        if not isinstance(ref, dict):
            continue
        ref_type = (ref.get("type") or "").strip().lower()
        url = _safe_str(ref.get("url"))
        if not url:
            continue

        if ref_type == "vcs":
            vcs_urls.append(url)
        else:
            other_urls.append(url)

    return vcs_urls, other_urls


def extract_license_ids_or_names(component: dict[str, Any]) -> list[str]:
    """
    Extract license identifiers/names from a CycloneDX component.

    Supports typical CycloneDX JSON patterns, e.g.:
      "licenses": [
        { "license": { "id": "Apache-2.0", "name": "Apache License 2.0" } }
      ]
    and expressions:
      "licenses": [
        { "expression": "MIT OR Apache-2.0" }
      ]

    Returns:
      A deduped list of strings. Prefers SPDX id when present, else name,
      else expression.
    """
    results: list[str] = []

    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return results

    for item in licenses:
        if not isinstance(item, dict):
            continue

        # CycloneDX license expression form
        expr = _safe_str(item.get("expression"))
        if expr:
            results.append(expr)
            continue

        # CycloneDX nested license form
        lic = item.get("license")
        if isinstance(lic, dict):
            lic_id = _safe_str(lic.get("id"))
            lic_name = _safe_str(lic.get("name"))
            # Prefer id; fall back to name
            results.append(lic_id or lic_name or "")
            continue

        # Some producers may flatten fields directly
        lic_id = _safe_str(item.get("id"))
        lic_name = _safe_str(item.get("name"))
        if lic_id or lic_name:
            results.append(lic_id or lic_name or "")
            continue

    # Clean + dedupe while preserving order
    cleaned: list[str] = []
    seen: set[str] = set()
    for r in results:
        r = (r or "").strip()
        if not r:
            continue
        if r in seen:
            continue
        seen.add(r)
        cleaned.append(r)

    return cleaned


def find_repo_url(component: dict[str, Any]) -> Optional[str]:
    vcs_urls, other_urls = extract_urls(component)

    for u in vcs_urls:
        norm = normalize_github_url(u)
        if norm:
            return norm

    for u in other_urls:
        norm = normalize_github_url(u)
        if norm:
            return norm

    return None


def _is_same_as_top_level(comp: dict[str, Any], top_level: dict[str, Any]) -> bool:
    """
    Determine whether `comp` in the components[] list is the same as metadata.component.

    Prefer bom-ref match; fall back to (group/namespace, name, version) match.
    """
    if not isinstance(top_level, dict) or not isinstance(comp, dict):
        return False

    top_ref = _bom_ref(top_level)
    comp_ref = _bom_ref(comp)
    if top_ref and comp_ref and top_ref == comp_ref:
        return True

    # Fallback match (best effort)
    return (
        _component_group_like(comp) == _component_group_like(top_level)
        and _safe_str(comp.get("name")) == _safe_str(top_level.get("name"))
        and _safe_str(comp.get("version")) == _safe_str(top_level.get("version"))
    )


# --- CycloneDX direct-dependency helpers ---

def _dependency_ref(d: dict[str, Any]) -> Optional[str]:
    # CycloneDX dependency objects commonly use "ref"; be tolerant of "bom-ref"/"bomRef"
    return _safe_str(d.get("ref")) or _bom_ref(d)


def _dependency_children(d: dict[str, Any]) -> list[str]:
    kids = d.get("dependsOn")
    if not isinstance(kids, list):
        return []
    out: list[str] = []
    for k in kids:
        s = _safe_str(k)
        if s:
            out.append(s)
    return out


def _compute_direct_dependency_refs(
    data: dict[str, Any],
    *,
    top_level: dict[str, Any],
) -> set[str]:
    """
    Return the set of bom-refs that are direct/top-level dependencies of the SBOM.

    Primary strategy:
      - Find metadata.component's bom-ref (top_ref)
      - In data["dependencies"], find the entry whose ref == top_ref
      - direct deps are that entry's dependsOn refs

    Fallback strategies:
      - If top_ref missing, try to derive it by matching metadata.component against components[]
      - If still unknown, infer "root" refs (refs that are not depended-on by anyone) and:
          - if exactly one root exists, treat its dependsOn as direct deps
          - otherwise return empty set (ambiguous)
    """
    deps = data.get("dependencies")
    if not isinstance(deps, list) or not deps:
        return set()

    # Build dep_map: ref -> dependsOn[]
    dep_map: dict[str, list[str]] = {}
    all_refs: set[str] = set()
    all_children: set[str] = set()

    for d in deps:
        if not isinstance(d, dict):
            continue
        ref = _dependency_ref(d)
        if not ref:
            continue
        kids = _dependency_children(d)
        dep_map[ref] = kids
        all_refs.add(ref)
        all_children.update(kids)

    # Try to get top_ref directly from metadata.component
    top_ref = _bom_ref(top_level)

    # If metadata.component has no bom-ref, try to find matching component in components[] and use its bom-ref
    if not top_ref:
        comps = data.get("components")
        if isinstance(comps, list) and top_level:
            for c in comps:
                if not isinstance(c, dict):
                    continue
                if _is_same_as_top_level(c, top_level):
                    top_ref = _bom_ref(c)
                    if top_ref:
                        break

    # Primary: metadata.component ref -> dependsOn
    if top_ref and top_ref in dep_map:
        return set(dep_map.get(top_ref, []) or [])

    # Fallback: infer roots (refs not depended on by any other)
    roots = list(all_refs - all_children)
    if len(roots) == 1:
        return set(dep_map.get(roots[0], []) or [])

    # Ambiguous or cannot determine
    return set()


def parse_sbom(sbom_path: Path) -> list[Component]:
    data = json.loads(sbom_path.read_text(encoding="utf-8"))

    # Identify the top-level (project) component, but DO NOT yield/create a Component from it.
    top_level = data.get("metadata", {}).get("component")
    if not isinstance(top_level, dict):
        top_level = {}

    # compute direct/top-level dependency refs from the SBOM dependency graph
    direct_refs = _compute_direct_dependency_refs(data, top_level=top_level)

    components: list[Component] = []

    comps = data.get("components")
    if isinstance(comps, list):
        for c in comps:
            if not isinstance(c, dict):
                continue

            # Skip if this component is the same as metadata.component
            if top_level and _is_same_as_top_level(c, top_level):
                continue

            group = _component_group_like(c)
            name = _safe_str(c.get("name")) or ""

            # used to decide direct vs transitive
            comp_ref = _bom_ref(c)
            is_direct = bool(comp_ref and comp_ref in direct_refs)

            components.append(
                Component(
                    name=name,
                    group=group,
                    version=_safe_str(c.get("version")),
                    publisher=_safe_str(c.get("publisher")),
                    description=_safe_str(c.get("description")),
                    licenses=extract_license_ids_or_names(c),
                    repo_url=find_repo_url(c),
                    is_direct=is_direct,
                )
            )

    return components


def resolve_output_path(input_path: Path, output_arg: Optional[str]) -> Path:
    if not output_arg:
        return input_path.with_suffix(".components.json")

    out = Path(output_arg)

    if out.exists() and out.is_dir():
        out.mkdir(parents=True, exist_ok=True)
        return out / f"{input_path.stem}.components.json"

    s = output_arg.strip()
    if s.endswith(("/", "\\")):
        out.mkdir(parents=True, exist_ok=True)
        return out / f"{input_path.stem}.components.json"

    out.parent.mkdir(parents=True, exist_ok=True)
    return out


def sibling_missing_repo_path(full_components_path: Path) -> Path:
    stem = full_components_path.stem
    suffix = full_components_path.suffix
    return full_components_path.with_name(f"{stem}.missing-repo{suffix}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse a CycloneDX SBOM.json and extract component fields.")
    ap.add_argument(
        "--input",
        default=None,
        help="Path to SBOM.json (CycloneDX).")
    ap.add_argument(
        "--output",
        default=f"{Path(Config.root_dir, "output", Config.project_name)}.components.json",
        help="Optional path to write extracted data as JSON (default: <input>.components.json).",
    )
    ap.add_argument(
        "--dedupe",
        default=True,
        action="store_true",
        help="Dedupe identical (group,name,version) rows before writing.",
    )
    args = ap.parse_args()

    if Config.sbom_gen_output_dir and Config.sbom_gen_output_file:
        args.input = f"{Path(Config.root_dir, Config.sbom_gen_output_dir, Config.sbom_gen_output_file)}{Config.sbom_extension}"
    if not args.input:
        sys.exit("No SBOM found for parsing.")

    in_path = Path(args.input).resolve()
    if not in_path.exists():
        print(f"ERROR: input file not found: {in_path}")
        return 2

    components = parse_sbom(in_path)

    if args.dedupe:
        seen: set[tuple[Optional[str], str, Optional[str]]] = set()
        deduped: list[Component] = []
        for c in components:
            key = (c.group, c.name, c.version)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(c)
        components = deduped

    # Build a store (handy for callers)
    Config.component_store = ComponentStore()
    Config.component_store.add_components(components)

    # Write full components list
    out_path = Path(args.output).resolve() if args.output else in_path.with_suffix(".components.json")
    out_path.write_text(json.dumps([asdict(c) for c in Config.component_store.get_all_components()], indent=2), encoding="utf-8")

    # Write missing-repo subset
    out_path = f"{Path(Config.root_dir, "output", Config.project_name)}.components.json"
    missing_repo = [c for c in Config.component_store.get_all_components() if not (c.repo_url and c.repo_url.strip())]
    missing_path = sibling_missing_repo_path(Path(out_path).resolve())
    missing_path.write_text(json.dumps([asdict(c) for c in missing_repo], indent=2), encoding="utf-8")

    print(f"Parsed {len(Config.component_store.get_all_components())} components")
    print(f"Wrote full list:     {out_path}")
    print(f"Wrote missing repo:  {missing_path} ({len(missing_repo)} components)")

    # Example lookups (comment out if you don't want these)
    # print(store.get_component_by_name("log4j"))
    # print(store.get_component_by_repo_url("git@github.com:owner/repo.git"))
    # print(store.get_component_by_name_and_group("commons-lang3", "org.apache.commons"))


if __name__ == "__main__":
    main()
