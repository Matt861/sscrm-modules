import json
import math
import os
import re
from pathlib import Path
from typing import Union, Any, Optional
from urllib.parse import urlparse

p = Path(__file__).resolve()

def load_env_vars(filepath=Path(".env").resolve()):
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    os.environ[key] = value
    except FileNotFoundError:
        print(f"Warning: {filepath} file not found.")


def read_json_file(json_path: Union[str, Path], encoding: str = "utf-8") -> Any:
    """
    Read and parse a JSON file.

    Returns:
        The parsed JSON content (usually a dict or list).

    Raises:
        FileNotFoundError: if the file doesn't exist
        ValueError: if the JSON is invalid
        OSError: for other file I/O errors
    """
    path = Path(json_path)

    try:
        with path.open("r", encoding=encoding) as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"JSON file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path} (line {e.lineno}, col {e.colno}): {e.msg}") from e


def iter_properties(data: Any):
    """
    Yields (property_path, value) pairs for a JSON object.

    - If `data` is a dict, returns each key/value.
    - If `data` is a list, returns each index/value.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            yield k, v
    elif isinstance(data, list):
        for i, v in enumerate(data):
            yield f"[{i}]", v
    else:
        # scalar root (string/number/bool/null)
        yield "", data

def load_json_file(json_file):
    with open(json_file, "r", encoding="utf-8") as file:
        json_data = json.load(file)
    return json_data

def round_to_int(value):
    rounded_int_value = int(round(value))
    return rounded_int_value

def _coerce_float(v: Any, default: float = 0.0) -> float:
    try:
        f = float(v)
        if math.isfinite(f):
            return f
        return default
    except Exception:
        return default

def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


GIT_SSH_RE = re.compile(r"^git@github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?$")


def normalize_github_url(raw: str) -> Optional[str]:
    """
    If raw matches one of the accepted GitHub URL forms, normalize to:
      https://github.com/owner/repo
    Otherwise return None.

    Notes:
    - For http(s), accepts URLs that include extra path segments (e.g., /tree/...),
      but normalizes down to /owner/repo.
    - Strips trailing .git from repo.
    """
    if not raw:
        return None

    s = raw.strip()

    # SSH form: git@github.com:owner/repo.git
    m = GIT_SSH_RE.match(s)
    if m:
        owner, repo = m.group(1), m.group(2)
        repo = repo[:-4] if repo.endswith(".git") else repo
        return f"https://github.com/{owner}/{repo}"

    # HTTP(S) forms
    try:
        u = urlparse(s)
    except Exception:
        return None

    if u.scheme not in ("http", "https"):
        return None
    if u.netloc.lower() != "github.com":
        return None

    # Path should start with /owner/repo...
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        return None

    owner, repo = parts[0], parts[1]
    repo = repo[:-4] if repo.endswith(".git") else repo

    if not owner or not repo:
        return None

    return f"https://github.com/{owner}/{repo}"
