#!/usr/bin/env python3
"""
pdf_fields_dump.py

List names + values of all form fields in a PDF (AcroForms):
- Text fields
- Checkboxes
- Radio groups
- Dropdowns/listboxes
- Signatures (name only, usually)

Usage:
  python pdf_fields_dump.py path/to/file.pdf
"""

from __future__ import annotations

from pathlib import Path

from configuration import Configuration as Config
import sys
from typing import Any, Dict, List, Optional, Tuple

# pypdf is the actively maintained fork of PyPDF2
# pip install pypdf
from pypdf import PdfReader
from pypdf.generic import NameObject


def _to_str(v: Any) -> str:
    """Best-effort string conversion for PDF objects."""
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return repr(v)


def _field_type_from_ft(ft: Any) -> str:
    """
    Map /FT (Field Type) to a friendly label:
      /Tx = text
      /Btn = button (checkbox/radio/push)
      /Ch = choice (combo/list)
      /Sig = signature
    """
    s = _to_str(ft).strip()
    if s.endswith("/Tx") or s == "/Tx":
        return "text"
    if s.endswith("/Btn") or s == "/Btn":
        return "button (checkbox/radio/push)"
    if s.endswith("/Ch") or s == "/Ch":
        return "choice (combo/list)"
    if s.endswith("/Sig") or s == "/Sig":
        return "signature"
    return f"unknown ({s})" if s else "unknown"


def _looks_like_xfa(reader: PdfReader) -> bool:
    """Detect XFA presence in the PDF catalog (common reason 'fields' appear empty)."""
    try:
        root = reader.trailer["/Root"]
        acroform = root.get("/AcroForm")
        if not acroform:
            return False
        # XFA can be an array or stream under /XFA
        return "/XFA" in acroform
    except Exception:
        return False


def _extract_checkbox_or_radio_state(annot: Dict[str, Any]) -> Tuple[str, str]:
    """
    For /Btn widgets, the /V (value) often holds the selected state name.
    Widgets may also have /AS (appearance state).
    Return (value, appearance_state) as strings.
    """
    v = _to_str(annot.get("/V"))
    as_ = _to_str(annot.get("/AS"))
    return v, as_


def dump_form_fields(pdf_path: str) -> List[Dict[str, Any]]:
    reader = PdfReader(pdf_path)

    fields = reader.get_fields()  # type: ignore[assignment]
    # get_fields() returns dict: { field_name: field_dict }
    # or None if no AcroForm fields.
    if not fields:
        if _looks_like_xfa(reader):
            print("No AcroForm fields found, but /XFA is present. This PDF is likely an XFA form.")
            print("AcroForm-style extraction won't work reliably for XFA. You may need an XFA-capable tool.")
        else:
            print("No AcroForm fields found in this PDF.")
        return []

    results: List[Dict[str, Any]] = []

    for name, info in fields.items():
        # pypdf returns a dict-like field info
        ft = info.get("/FT")
        field_type = _field_type_from_ft(ft)

        # /V is the field value; sometimes /DV (default value) is useful too
        value = info.get("/V")
        default_value = info.get("/DV")

        # Some fields also have options (/Opt) for dropdown/list
        options = info.get("/Opt")

        # For buttons, try to show checkbox/radio state more clearly
        btn_extra = {}
        if _to_str(ft) in ("/Btn", "NameObject('/Btn')") or field_type.startswith("button"):
            v, as_ = _extract_checkbox_or_radio_state(info)
            btn_extra = {"button_value": v, "appearance_state": as_}

        row = {
            "name": name,
            "type": field_type,
            "value": _to_str(value),
            "default_value": _to_str(default_value),
            "options": options if options is None else _to_str(options),
            **btn_extra,
        }
        results.append(row)

    return results


def main() -> int:

    pdf_path = f"{Config.root_dir}/templates/gray_sis_template_modified.pdf"
    try:
        rows = dump_form_fields(pdf_path)
    except FileNotFoundError:
        print(f"File not found: {pdf_path}")
        return 2
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return 1

    if not rows:
        return 0

    output_file = Path(Config.root_dir, "output/gray_sis_fields_3.txt")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8", newline="\n") as out:
        print(f"Found {len(rows)} field(s):\n", file=out)
        for r in rows:
            print(f"- Name:  {r['name']}", file=out)
            print(f"  Type:  {r['type']}", file=out)
            print(f"  Value: {r['value']}", file=out)
            if r.get("default_value"):
                print(f"  Default: {r['default_value']}", file=out)
            if r.get("options"):
                print(f"  Options: {r['options']}", file=out)
            if "button_value" in r or "appearance_state" in r:
                print(f"  Button /V:  {r.get('button_value', '')}", file=out)
                print(f"  Widget /AS: {r.get('appearance_state', '')}", file=out)
            print(file=out)  # blank line

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
