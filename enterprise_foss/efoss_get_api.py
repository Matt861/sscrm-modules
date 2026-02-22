from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from python_graphql_client import GraphqlClient

from configuration import Configuration as Config
from loggers.efoss_get_api_logger import efoss_get_api_logger as logger
from models.efoss_data import EnterpriseFossData


# ----------------------------
# GraphQL
# ----------------------------

FOSS_COMPONENT_QUERY = """
query FossComponentRecords($id: String!) {
  fossComponentRecords(ids: $id) {
    name
    version
    approvalStatus
    downloadUrls
    sourceCodeUrl
    url
    usageConditions {
      conditionText
      conditionType
      associatedLicenses
    }
    useCaseRisk {
      use
      distribution
      internalCombining
    }
    licenses {
      licenseText
      licenseId
      licenseName
    }
  }
}
"""


def _normalize_group(group: Optional[str]) -> str:
    return group or ""


def _build_component_id(
    *,
    repo: str,
    name: str,
    version: str,
    group: Optional[str],
    component_os: str = "",
) -> str:
    """
    Matches your existing ID formats:
      - raw:  repo:os:group:name:version
      - else: repo:group:name:version
    """
    g = _normalize_group(group)

    if repo == "raw":
        return f"{repo}:{component_os.lower()}:{g}:{name}:{version}"

    return f"{repo}:{g}:{name}:{version}"


# ----------------------------
# Retry + cache helpers
# ----------------------------

@dataclass(frozen=True)
class ComponentKey:
    repo: str
    group: str
    name: str
    version: str
    component_os: str = ""


def _execute_with_retries(
    client: GraphqlClient,
    *,
    query: str,
    variables: Dict[str, Any],
    retries: int = 3,
    backoff_seconds: float = 0.75,
) -> Dict[str, Any]:
    """
    Basic retry loop for transient network/API hiccups.
    """
    import time

    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            return client.execute(query=query, variables=variables)
            # If your client doesn't support variables, you can fall back to:
            # return client.execute(query=query % variables)
        except Exception as e:
            last_exc = e
            if attempt == retries:
                raise
            sleep_for = backoff_seconds * (2 ** (attempt - 1))
            logger.warning(
                "GraphQL call failed (attempt %s/%s). Retrying in %.2fs. Error: %s",
                attempt,
                retries,
                sleep_for,
                e,
            )
            time.sleep(sleep_for)

    # logically unreachable
    raise last_exc or RuntimeError("Unknown error executing GraphQL")


# ----------------------------
# Transform response -> model
# ----------------------------

def _parse_foss_component_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Handles both:
      - normal data responses
      - GraphQL errors returned in payload["errors"]
    """
    if not isinstance(payload, dict):
        return []

    if payload.get("errors"):
        # Log GraphQL-level errors, but don't crash the whole run.
        logger.warning("GraphQL returned errors: %s", payload.get("errors"))

    return (payload.get("data") or {}).get("fossComponentRecords") or []


def _set_component_efoss_data(component: Any, record: Dict[str, Any]) -> None:
    """
    Maps the first record into EnterpriseFossData and assigns component.efoss_data.
    """
    usage_conditions = record.get("usageConditions") or []
    licenses = record.get("licenses") or []
    use_case_risk = record.get("useCaseRisk")

    component.efoss_data = EnterpriseFossData(
        name=component.name,
        version=component.version,
        group=getattr(component, "group", None),
        approval_status=record.get("approvalStatus"),
        url=record.get("url"),
        source_code_url=record.get("sourceCodeUrl"),
        usage_conditions=list(usage_conditions),
        use_case_risk=use_case_risk,
        licenses=list(licenses),
    )


# ----------------------------
# Main flow
# ----------------------------

def enrich_components_with_efoss_data(
    client: GraphqlClient,
    *,
    repo: str,
    component_os: str = "",
    enable_cache: bool = True,
) -> None:
    """
    Iterates over components in the store and populates component.efoss_data.
    """
    cache: Dict[ComponentKey, List[Dict[str, Any]]] = {}

    components = Config.component_store.get_all_components()
    logger.info("Starting eFOSS enrichment for %d component(s). repo=%s", len(components), repo)

    for idx, component in enumerate(components, start=1):
        name = getattr(component, "name", "")
        version = getattr(component, "version", "")
        group = getattr(component, "group", None)

        if not name or not version:
            logger.warning("Skipping component missing name/version: %r", component)
            continue

        key = ComponentKey(
            repo=repo,
            group=_normalize_group(group),
            name=name,
            version=version,
            component_os=component_os,
        )

        try:
            if enable_cache and key in cache:
                records = cache[key]
            else:
                comp_id = _build_component_id(
                    repo=repo,
                    name=name,
                    version=version,
                    group=group,
                    component_os=component_os,
                )

                logger.info("[%d/%d] Querying eFOSS for id=%s", idx, len(components), comp_id)

                payload = _execute_with_retries(
                    client,
                    query=FOSS_COMPONENT_QUERY,
                    variables={"id": comp_id},
                    retries=3,
                    backoff_seconds=0.75,
                )

                records = _parse_foss_component_records(payload)
                if enable_cache:
                    cache[key] = records

            if records:
                _set_component_efoss_data(component, records[0])
            else:
                # Optional: explicit None assignment so downstream knows it was checked.
                component.efoss_data = None

        except Exception as e:
            logger.exception(
                "Error retrieving component record for %s:%s:%s. Error: %s",
                name,
                _normalize_group(group),
                version,
                e,
            )

    # Keep your existing behavior
    Config.component_store.reindex()
    logger.info("Finished eFOSS enrichment. Component store reindexed.")


def main() -> None:
    auth = (Config.efoss_user, Config.efoss_token)
    client = GraphqlClient(
        endpoint=Config.efoss_api_url,
        auth=auth,
        verify=Config.cert_file,
    )

    enrich_components_with_efoss_data(
        client,
        repo=Config.package_manager,
        component_os="",  # set if you actually have an OS value for raw repo
        enable_cache=True,
    )


if __name__ == "__main__":
    main()