#!/usr/bin/env python3
"""
pdf_form_edit.py

Edit AcroForm PDF fields:
- Set field values (text, choice, checkbox, radio)
- Rename fields (change the /T name)
- Optionally list fields

Install:
  pip install pypdf

Usage examples:
  # List all fields
  python pdf_form_edit.py input.pdf output.pdf --list

  # Set text field value
  python pdf_form_edit.py input.pdf output.pdf --set "full.field.name=Hello world"

  # Set checkbox on/off (accepts true/false/yes/no/on/off/1/0)
  python pdf_form_edit.py input.pdf output.pdf --set "agree_terms=true"

  # Set a radio group by export value (often the appearance name; script tries to match)
  python pdf_form_edit.py input.pdf output.pdf --set "gender=Male"

  # Rename a field (old=new). Note: "new" should usually be a simple name (no hierarchy).
  python pdf_form_edit.py input.pdf output.pdf --rename "oldFieldName=newFieldName"

Notes:
- This works for AcroForms. If your PDF is XFA-based, the fields may not be editable this way.
- Many PDF viewers require NeedAppearances=true to visually show updated values; this script sets it.
"""

from __future__ import annotations
from configuration import Configuration as Config
import argparse
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, TextStringObject, DictionaryObject, BooleanObject
from pypdf.constants import FieldDictionaryAttributes as FDA

TRUTHY = {"true", "1", "yes", "y", "on", "checked"}
FALSY = {"false", "0", "no", "n", "off", "unchecked"}


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return repr(v)


def _is_xfa(reader: PdfReader) -> bool:
    try:
        root = reader.trailer["/Root"]
        acro = root.get("/AcroForm")
        if not acro:
            return False
        acro = acro.get_object() if hasattr(acro, "get_object") else acro
        return "/XFA" in acro
    except Exception:
        return False


def _deref(obj):
    return obj.get_object() if hasattr(obj, "get_object") else obj


def _iter_all_field_dicts(acroform: Any) -> Iterable[Any]:
    """
    Walk /AcroForm /Fields recursively, yielding field dictionaries (and widgets if embedded).
    """
    acroform = _deref(acroform)
    fields = acroform.get("/Fields") or []
    for fref in fields:
        yield from _walk_field(_deref(fref))


def _walk_field(field: Any) -> Iterable[Any]:
    yield field
    kids = field.get("/Kids")
    if kids:
        for kid in kids:
            yield from _walk_field(_deref(kid))


def _full_field_name(field: Any) -> str:
    """
    Compute a "full" field name by walking /Parent chain and joining /T parts.
    """
    parts: List[str] = []
    cur = field
    # Walk upward through parents
    while cur:
        t = cur.get("/T")
        if t is not None:
            parts.append(_as_str(t))
        parent = cur.get("/Parent")
        cur = _deref(parent) if parent else None
    # parts were collected from leaf->root
    parts.reverse()
    # Filter empties
    parts = [p for p in parts if p]
    return ".".join(parts)


def _field_ft(field: Any) -> str:
    ft = field.get("/FT")
    s = _as_str(ft)
    # Normalize common cases
    if s.endswith("/Tx") or s == "/Tx":
        return "/Tx"
    if s.endswith("/Btn") or s == "/Btn":
        return "/Btn"
    if s.endswith("/Ch") or s == "/Ch":
        return "/Ch"
    if s.endswith("/Sig") or s == "/Sig":
        return "/Sig"
    return s  # unknown/empty


def _set_need_appearances(writer):
    root = writer._root_object
    acro = root.get("/AcroForm")

    # If the PDF has no AcroForm yet, create one
    if acro is None:
        acro = DictionaryObject()
        root[NameObject("/AcroForm")] = acro
    else:
        acro = _deref(acro)

    # MUST be a PdfObject (BooleanObject), not a Python bool
    acro[NameObject("/NeedAppearances")] = BooleanObject(True)


def _parse_set_arg(s: str) -> Tuple[str, str]:
    if "=" not in s:
        raise ValueError(f'--set expects "name=value", got: {s!r}')
    name, val = s.split("=", 1)
    return name.strip(), val


def _parse_rename_arg(s: str) -> Tuple[str, str]:
    if "=" not in s:
        raise ValueError(f'--rename expects "old=new", got: {s!r}')
    old, new = s.split("=", 1)
    return old.strip(), new.strip()


def _boolish(value: str) -> Optional[bool]:
    v = value.strip().lower()
    if v in TRUTHY:
        return True
    if v in FALSY:
        return False
    return None


def _nameobj(name: str) -> NameObject:
    # Ensure leading slash for NameObject values like /Yes, /Off
    n = name.strip()
    if not n.startswith("/"):
        n = "/" + n
    return NameObject(n)


def _get_widgets(field: Any) -> List[Any]:
    """
    For buttons/radios/checkboxes, the actual widget annotations can be:
    - embedded in /Kids
    - or the field itself
    """
    kids = field.get("/Kids")
    if kids:
        return [_deref(k) for k in kids]
    return [field]


def _extract_on_states_from_widget(widget: Any) -> List[str]:
    """
    Read appearance states from /AP /N keys. Typically includes /Off and one or more "on" names.
    """
    ap = widget.get("/AP")
    if not ap:
        return []
    ap = _deref(ap)
    n = ap.get("/N")
    if not n:
        return []
    n = _deref(n)
    # Keys are NameObjects like /Off, /Yes, /On, /Choice1...
    return [str(k) for k in n.keys()]


def _set_text_or_choice(field: Any, value: str) -> None:
    field[NameObject("/V")] = TextStringObject(value)
    # Optionally also set /DV (default); comment out if you don't want this behavior
    # field[NameObject("/DV")] = TextStringObject(value)


def _set_checkbox(field: Any, checked: bool) -> None:
    widgets = _get_widgets(field)

    # Pick an "on" state name from any widget appearance (/AP /N)
    on_name: Optional[str] = None
    for w in widgets:
        states = _extract_on_states_from_widget(w)
        # choose first non-/Off
        for st in states:
            if st != "/Off":
                on_name = st
                break
        if on_name:
            break

    # Fallback if appearances missing: use /Yes as a common convention
    if on_name is None:
        on_name = "/Yes"

    if checked:
        field[NameObject("/V")] = _nameobj(on_name)
        for w in widgets:
            w[NameObject("/AS")] = _nameobj(on_name)
    else:
        field[NameObject("/V")] = _nameobj("/Off")
        for w in widgets:
            w[NameObject("/AS")] = _nameobj("/Off")


def _set_radio_group(field: Any, desired: str) -> None:
    """
    Set a radio group to a specific export value.
    We attempt to match the desired value against widget appearance "on" states.
    """
    widgets = _get_widgets(field)
    desired_norm = desired.strip()
    desired_slash = desired_norm if desired_norm.startswith("/") else "/" + desired_norm

    # Map widget -> its "on" state(s)
    widget_on_states: List[Tuple[Any, List[str]]] = []
    all_on_states: List[str] = []
    for w in widgets:
        states = _extract_on_states_from_widget(w)
        on_states = [s for s in states if s != "/Off"]
        widget_on_states.append((w, on_states))
        all_on_states.extend(on_states)

    # Try exact match (/Male) or case-insensitive match (Male vs /Male)
    chosen_state: Optional[str] = None
    if desired_slash in all_on_states:
        chosen_state = desired_slash
    else:
        # case-insensitive match without leading slash
        dn = desired_norm.lower()
        for st in all_on_states:
            if st.lstrip("/").lower() == dn:
                chosen_state = st
                break

    if chosen_state is None:
        # If we can't find a match, still set /V to the desired name; appearances may not match though.
        chosen_state = desired_slash

    field[NameObject("/V")] = _nameobj(chosen_state)

    # Update each widget appearance state: selected gets chosen_state, others Off
    for w, on_states in widget_on_states:
        if chosen_state in on_states:
            w[NameObject("/AS")] = _nameobj(chosen_state)
        else:
            w[NameObject("/AS")] = _nameobj("/Off")


def _set_button(field: Any, value: str) -> None:
    """
    Decide if /Btn is checkbox-like (boolean) or radio-like (select one value).
    - If value parses as bool => treat as checkbox.
    - Else => treat as radio group selection by export value.
    """
    b = _boolish(value)
    if b is not None:
        _set_checkbox(field, b)
    else:
        _set_radio_group(field, value)


def _find_rename_node(obj: dict) -> dict:
    cur = obj
    while cur is not None and ("/T" not in cur and "/TM" not in cur):
        parent = cur.get("/Parent")
        cur = parent.get_object() if parent and hasattr(parent, "get_object") else (parent if isinstance(parent, dict) else None)
    return cur or obj


def _rename_field(field: dict, new_name: str) -> None:
    # Update common “name” keys that different tools/viewers display
    for key in ("/T", "/TM", "/TU"):
        if key in field:
            field[NameObject(key)] = TextStringObject(new_name)

    # Some PDFs store/duplicate info on widget kids too
    kids = field.get("/Kids")
    if kids:
        for kid_ref in kids:
            kid = kid_ref.get_object() if hasattr(kid_ref, "get_object") else kid_ref
            if isinstance(kid, dict):
                for key in ("/T", "/TM", "/TU"):
                    if key in kid:
                        kid[NameObject(key)] = TextStringObject(new_name)


@dataclass
class FieldEntry:
    full_name: str
    field: Any
    ft: str


def _build_field_index(writer: PdfWriter) -> Dict[str, List[FieldEntry]]:
    root = writer._root_object
    acro = root.get("/AcroForm")
    if not acro:
        return {}
    acro = _deref(acro)
    index: Dict[str, List[FieldEntry]] = {}
    for f in _iter_all_field_dicts(acro):
        # Only consider dictionaries that have /T (field name part)
        if "/T" not in f and f.get("/Parent") is None:
            continue
        full = _full_field_name(f)
        if not full:
            continue
        ft = _field_ft(f)
        index.setdefault(full, []).append(FieldEntry(full, f, ft))
    return index


def list_fields(writer: PdfWriter) -> None:
    idx = _build_field_index(writer)
    if not idx:
        print("No AcroForm fields found.")
        return
    print(f"Found {sum(len(v) for v in idx.values())} field node(s):\n")
    for name in sorted(idx.keys()):
        for ent in idx[name]:
            val = _as_str(ent.field.get("/V"))
            print(f"- {name}  (FT={ent.ft or 'unknown'})  V={val}")


def apply_changes(
    writer: PdfWriter,
    sets: List[Tuple[str, str]],
    renames: List[Tuple[str, str]],
    strict: bool,
) -> None:
    idx = _build_field_index(writer)

    def resolve(name: str) -> List[FieldEntry]:
        hits = idx.get(name, [])
        if not hits and strict:
            raise KeyError(f"Field not found: {name}")
        return hits

    # Renames first (so subsequent sets can refer to the new name if desired)
    # for old, new in renames:
    #     hits = resolve(old)
    #     for ent in hits:
    #         node = _find_rename_node(ent.field)  # climbs to the actual field if needed
    #         _rename_field(node, new, rename_tm=True, rename_tu=False)

    for old, new in renames:
        hits = resolve(old)
        for ent in hits:
            _rename_field(ent.field, new)

    # Rebuild index after renames so set operations can find new names
    idx = _build_field_index(writer)

    for name, value in sets:
        hits = resolve(name)
        for ent in hits:
            ft = ent.ft
            if ft == "/Tx" or ft == "/Ch" or ft == "/Sig" or not ft:
                # Text/choice/signature/unknown: try setting as string
                _set_text_or_choice(ent.field, value)
            elif ft == "/Btn":
                _set_button(ent.field, value)
            else:
                # Unknown type: set /V as string
                _set_text_or_choice(ent.field, value)


def main() -> int:
    # ap = argparse.ArgumentParser()
    # ap.add_argument("input_pdf", help="Input PDF path")
    # ap.add_argument("output_pdf", help="Output PDF path")
    # ap.add_argument("--list", action="store_true", help="List fields and exit (still writes output if other edits given)")
    # ap.add_argument("--set", action="append", default=[], help='Set a field value: "name=value" (repeatable)')
    # ap.add_argument("--rename", action="append", default=[], help='Rename a field: "old=new" (repeatable)')
    # ap.add_argument("--strict", action="store_true", help="Fail if a referenced field name is not found")
    # args = ap.parse_args()

    # reader = PdfReader(args.input_pdf)
    reader = PdfReader(f"{Config.root_dir}/templates/gray_sis_template_with_values_2025.pdf")
    output_pdf = f"{Config.root_dir}/output/gray_sis_template_modified.pdf"
    strict = True
    list_pdf_fields = False

    # # 1) Rename fields: (old_name, new_name)
    # renames = [
    #     ("oldFieldName", "newFieldName"),
    #     ("agree_terms_old", "agreeTerms"),
    # ]
    #
    # # 2) Set field values: (field_name, value_as_string)
    # sets = [
    #     ("newFieldName", "Hello from Python!"),  # text field
    #     ("agreeTerms", "true"),                  # checkbox (true/false/on/off/1/0)
    #     ("gender", "Male"),                      # radio group (export value)
    #     ("country", "United States"),            # dropdown/choice field
    # ]

    renames = [
        ("Individual Requesting Software-0", "Individual Requesting Software")
    ]

    sets = [
        ("Individual Requesting Software", "Matthew Windham")
    ]

    if _is_xfa(reader):
        print("WARNING: This PDF appears to contain XFA (/XFA present).")
        print("AcroForm field renaming/setting may not work for XFA-based forms.\n")

    writer = PdfWriter()
    # Clone full document (preserves form structure better than append_pages)
    writer.clone_document_from_reader(reader)

    # Ensure viewers refresh appearance streams for updated values
    _set_need_appearances(writer)

    # Parse operations
    # sets: List[Tuple[str, str]] = []
    # for s in args.set:
    #     sets.append(_parse_set_arg(s))
    #
    # renames: List[Tuple[str, str]] = []
    # for r in args.rename:
    #     renames.append(_parse_rename_arg(r))

    if list_pdf_fields:
        list_fields(writer)
        print()

    if sets or renames:
        try:
            apply_changes(writer, sets, renames, strict=strict)
        except Exception as e:
            print(f"Error applying changes: {e}")
            return 1

    # Write output
    with open(output_pdf, "wb") as f:
        writer.write(f)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
