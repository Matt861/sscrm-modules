import sys
from pathlib import Path
from typing import Any, Generator, Optional
import utils
from loggers.maven_sbom_gen_logger import maven_sbom_gen_logger as logger
from configuration import Configuration as Config


def find_values_by_key(obj: Any, key: str) -> Generator[Any, None, None]:
    """
    Recursively search obj (which may be a dict/list/primitive) for keys equal to `key`.
    Yields each matching value found.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            # Recurse into value
            yield from find_values_by_key(v, key)
    elif isinstance(obj, list):
        for item in obj:
            yield from find_values_by_key(item, key)
    # primitives have no children; do nothing


def find_first_value_by_key(obj: Any, key: str) -> Optional[Any]:
    """Return the first matching value for `key` or None if none found."""
    for v in find_values_by_key(obj, key):
        return v
    return None


def main() -> None:

    repo_urls_json_name = f"github_urls_{Config.package_manager}.json"
    repo_urls_json_path = Path(Config.root_dir, "input/urls/github", repo_urls_json_name)

    try:
        repo_urls_json_data = utils.load_json_file(repo_urls_json_path)
    except Exception as e:
        print(logger.error(f"Error loading JSON file: {e}", file=sys.stderr))
        sys.exit()

    for component in Config.component_store.get_all_components():
        if not component.repo_url:
            repo_url = find_first_value_by_key(repo_urls_json_data, component.name)
            if repo_url:
                component.repo_url = repo_url


if __name__ == "__main__":
    main()