from dataclasses import dataclass
from typing import Optional, Iterable, List, Dict, Tuple

from models.repo import RepositoryInfo
from utils import normalize_github_url


@dataclass
class Component:
    name: str
    group: Optional[str]
    version: Optional[str]
    publisher: Optional[str]
    description: Optional[str]
    licenses: Optional[list[str]]
    repo_url: Optional[str]
    is_direct: Optional[bool]

    repo_info: Optional[RepositoryInfo] = None


def set_repo_info_for_repo_url(
    components: List[Component],
    repo_url: str,
    repo_info: RepositoryInfo,
    *,
    normalize_fn,
) -> None:
    """
    Set repo_info for all components whose repo_url matches `repo_url`.

    Returns number of components updated.
    """
    target = (normalize_fn(repo_url) or repo_url).strip()
    #updated = 0

    for c in components:
        if not c.repo_url:
            continue
        current = (normalize_fn(c.repo_url) or c.repo_url).strip()
        if current == target:
            c.repo_info = repo_info
            #updated += 1

    #return updated


class ComponentStore:
    """
    Minimal in-memory store with a few retrieval methods.

    Note:
    - get_component_by_* methods return the FIRST match if multiple exist.
      (If you'd rather return a list of matches, tell me and I'll adjust.)
    """

    def __init__(self) -> None:
        self._components: List[Component] = []

        # simple indices for faster lookups
        self._by_name: Dict[str, List[Component]] = {}
        self._by_repo_url: Dict[str, List[Component]] = {}
        self._by_name_group: Dict[Tuple[str, Optional[str]], List[Component]] = {}

    def add_component(self, component: Component) -> None:
        self._components.append(component)

        # Index by name
        self._by_name.setdefault(component.name, []).append(component)

        # Index by repo_url (only if present)
        if component.repo_url:
            self._by_repo_url.setdefault(component.repo_url, []).append(component)

        # Index by (name, group) (group may be None)
        self._by_name_group.setdefault((component.name, component.group), []).append(component)

    def add_components(self, components: Iterable[Component]) -> None:
        for c in components:
            self.add_component(c)

    def get_component_by_name(self, name: str) -> Optional[Component]:
        matches = self._by_name.get(name) or []
        return matches[0] if matches else None

    def get_component_by_repo_url(self, repo_url: str) -> Optional[Component]:
        # normalize input if it's in one of the accepted github forms
        normalized = normalize_github_url(repo_url) or repo_url.strip()
        matches = self._by_repo_url.get(normalized) or []
        return matches[0] if matches else None

    def get_component_by_name_and_group(self, name: str, group: Optional[str]) -> Optional[Component]:
        matches = self._by_name_group.get((name, group)) or []
        return matches[0] if matches else None

    def get_all_components(self) -> List[Component]:
        return list(self._components)
