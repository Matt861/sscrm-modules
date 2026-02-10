import requests

from configuration import Configuration as Config
from typing import List, Dict, Any, Optional

from dtrack.dtrack_client import DependencyTrackClient


def get_project(project_name: str, project_version: Optional[str] = None) -> Dict[str, Any]:
    """
    Find and return a project by name and optional version.

    Tries server-side filtering via GET /api/v1/project?name=...&version=... first.
    If that is not supported, falls back to fetching all projects and filtering locally.

    If multiple projects match the given name and no version is provided, raises a ValueError
    describing the available versions/UUIDs so the caller can disambiguate.
    """
    # Try server-side query first (many DT instances support /project?name=...&version=...)
    params: Dict[str, Any] = {"name": project_name}
    if project_version:
        params["version"] = project_version

    try:
        resp = Config.dtrack_client.request("GET", "/project", params=params)
    except requests.HTTPError:
        # If server responded with an error for the query (unsupported params), fall back to fetching all projects
        resp = None

    projects: List[Dict[str, Any]] = []

    if resp is None:
        # Fallback: fetch all projects and filter locally
        all_projects = Config.dtrack_client.request("GET", "/project")
        if isinstance(all_projects, list):
            projects = [p for p in all_projects if p.get("name") == project_name]
        elif isinstance(all_projects, dict):
            # some servers return an object with items/results
            items = all_projects.get("items") or all_projects.get("projects") or all_projects.get("results") or []
            projects = [p for p in items if p.get("name") == project_name]
    else:
        # resp may be a single project dict or a list or an object with items
        if isinstance(resp, dict):
            # If resp looks like a single project (contains uuid/name/version), check it
            if "uuid" in resp and resp.get("name") == project_name and (
                    project_version is None or resp.get("version") == project_version
            ):
                return resp
            # Otherwise, resp might be an envelope with items
            items = resp.get("items") or resp.get("projects") or resp.get("results")
            if isinstance(items, list):
                projects = items
            else:
                # Single dict that didn't match -> no results
                projects = []
        elif isinstance(resp, list):
            projects = resp
        else:
            projects = []

        # Further filter to exact name/version match if server returned broader results
        projects = [p for p in projects if p.get("name") == project_name]

    # If version provided, filter by it
    if project_version:
        projects = [p for p in projects if p.get("version") == project_version]

    if not projects:
        raise LookupError(f"No project found with name='{project_name}'"
                          + (f" and version='{project_version}'" if project_version else ""))

    if len(projects) > 1 and not project_version:
        # Ambiguous: multiple versions exist for this project name
        choices = "\n".join(
            f"- version: {p.get('version')!r}, uuid: {p.get('uuid') or p.get('uuid')}" for p in projects
        )
        raise ValueError(
            f"Multiple projects found with name={project_name!r}. Provide project_version to disambiguate. "
            f"Available versions:\n{choices}"
        )

    # Return the first (and typically only) match
    return projects[0]


def find_projects(name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Search projects. The server supports query parameters; implementations may vary by version.
    This attempts to call GET /api/v1/project with a 'name' parameter if provided.
    If API doesn't support this on your installation, call get_project with a UUID instead.
    """
    params = {}
    if name:
        params["name"] = name

    if not params:
        return Config.dtrack_client.request("GET", "/project")
    else:
        return Config.dtrack_client.request("GET", "/project", params=params)

    #return Config.dtrack_client.request("GET", "/project") if not params else Config.dtrack_client.request("GET", "/project", params=params)


# Vulnerabilities
def get_project_vulnerabilities(project_uuid: str) -> List[Dict[str, Any]]:
    """
    Get vulnerabilities for a project.
    GET /api/v1/vulnerability/project/{projectUuid}
    """
    return Config.dtrack_client.request("GET", f"/vulnerability/project/{project_uuid}")

# Components (paginated)
def get_project_components(project_uuid: str, page_size: int = 100) -> List[Dict[str, Any]]:
    """
    Get all components for a project. Uses the component endpoint with pagination:
    GET /api/v1/component?project={projectUuid}&pageNumber=X&pageSize=Y
    Some Dependency-Track versions use different pagination parameter names; this is the common pattern.
    """
    components: List[Dict[str, Any]] = []
    page_number = 1

    while True:
        params = {"project": project_uuid, "pageNumber": page_number, "pageSize": page_size}
        page = Config.dtrack_client.request("GET", "/component", params=params)
        if not isinstance(page, list):
            # If the API returns an object with "items" or similar, try to adapt
            # Try common alternatives
            if isinstance(page, dict):
                items = page.get("items") or page.get("components") or page.get("results") or []
            else:
                items = []
        else:
            items = page

        if not items:
            break

        components.extend(items)

        # If less than page_size returned, we've reached the last page
        if isinstance(items, list) and len(items) < page_size:
            break

        page_number += 1

    return components


def main() -> None:
    if not Config.dtrack_api_key:
        raise SystemExit("ERROR: Dependency-Track API key missing.")

    try:
        Config.dtrack_project = get_project(Config.project_name, Config.project_version)
        print("Project:")
        print(Config.dtrack_project)

        project_uuid = Config.dtrack_project.get("uuid")
        if project_uuid:
            Config.dtrack_vulnerabilities = get_project_vulnerabilities(project_uuid)
            print(f"\nVulnerabilities (count={len(Config.dtrack_vulnerabilities)}):")
            for v in Config.dtrack_vulnerabilities:
                print(f"- {v.get('vulnId') or v.get('id')}: {v.get('title') or v.get('description', '')}")

            Config.dtrack_components = get_project_components(project_uuid)
            print(f"\nComponents (count={len(Config.dtrack_components)}):")
            for c in Config.dtrack_components:
                name = c.get("name")
                version = c.get("version")
                purl = c.get("purl")
                print(f"- {name} {version} (purl={purl})")
        else:
            print("Project has no UUID; cannot fetch vulnerabilities/components")

    except ValueError as ve:
        print(f"Ambiguous project: {ve}")
    except LookupError as le:
        print(f"Not found: {le}")
    except requests.HTTPError as e:
        print(f"HTTP error: {e} - response: {getattr(e.response, 'text', None)}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    Config.dtrack_client = DependencyTrackClient()
    Config.project_name = "crt-maven-dependencies"
    Config.project_version = "1.0.0"
    main()