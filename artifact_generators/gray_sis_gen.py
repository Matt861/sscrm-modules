import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Dict, Any, Iterable, Optional
from configuration import Configuration as Config
from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, TextStringObject, DictionaryObject
from input import gray_sis_field_dynamic_values

TRUTHY = {"true", "1", "yes", "y", "on", "checked"}
FALSY = {"false", "0", "no", "n", "off", "unchecked"}


def load_gray_sis_values(data: dict[str, str]) -> List[Tuple[str, str]]:
    """
    Reads a JSON dict of { old_name: new_name } and returns a list of (old, new) pairs.
    """
    #p = Path(json_path)
    #data = json.loads(json_path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"Rename JSON must be an object/dict, got: {type(data).__name__}")

    pdf_values: List[Tuple[str, str]] = []
    for old, new in data.items():
        if not isinstance(old, str) or not isinstance(new, str):
            raise ValueError("Rename JSON must map string->string.")
        old_s = old.strip()
        new_s = new.strip()
        if not old_s:
            raise ValueError("PDF values contains an empty field name.")
        pdf_values.append((old_s, new_s))

    return pdf_values


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


def _set_need_appearances(writer):
    root = writer._root_object
    acro = root.get("/AcroForm")

    # If the PDF has no AcroForm yet, create one
    if acro is None:
        acro = DictionaryObject()
        root[NameObject("/AcroForm")] = acro
    else:
        acro = _deref(acro)


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


@dataclass
class FieldEntry:
    full_name: str
    field: Any
    ft: str


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return repr(v)


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


def _set_text_or_choice(field: Any, value: str) -> None:
    field[NameObject("/V")] = TextStringObject(value)
    # Optionally also set /DV (default); comment out if you don't want this behavior
    # field[NameObject("/DV")] = TextStringObject(value)


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


def _boolish(value: str) -> Optional[bool]:
    v = value.strip().lower()
    if v in TRUTHY:
        return True
    if v in FALSY:
        return False
    return None


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


def apply_changes(writer: PdfWriter, gray_sis_values: List[Tuple[str, str]], strict: bool,) -> None:
    idx = _build_field_index(writer)

    def resolve(name: str) -> List[FieldEntry]:
        hits = idx.get(name, [])
        if not hits and strict:
            raise KeyError(f"Field not found: {name}")
        return hits

    for name, value in gray_sis_values:
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


def main() -> None:
    Config.gray_sis_pdf_file_name = f"{Config.project_name}-{Config.project_version}-gray-sis.pdf"
    gray_sis_pdf_path = Path(Config.project_output_dir, Config.gray_sis_pdf_file_name)
    gray_sis_field_values = gray_sis_field_dynamic_values.init_gray_field_dynamic_values()
    pdf_values = load_gray_sis_values(gray_sis_field_values)
    reader = PdfReader(f"{Path(Config.templates_dir, Config.gray_sis_template_name)}")

    strict = True

    if _is_xfa(reader):
        print("WARNING: This PDF appears to contain XFA (/XFA present).")
        print("AcroForm field renaming/setting may not work for XFA-based forms.\n")

    writer = PdfWriter()
    # Clone full document (preserves form structure better than append_pages)
    writer.clone_document_from_reader(reader)
    # Ensure viewers refresh appearance streams for updated values
    _set_need_appearances(writer)

    if pdf_values:
        try:
            apply_changes(writer, pdf_values, strict=strict)
        except Exception as e:
            print(f"Error applying values to gray sis: {e}")
            sys.exit()

    # Write output
    with open(gray_sis_pdf_path, "wb") as f:
        writer.write(f)


if __name__ == "__main__":
    main()