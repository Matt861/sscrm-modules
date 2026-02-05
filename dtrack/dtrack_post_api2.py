#!/usr/bin/env python3
"""
Upload an SBOM to OWASP Dependency-Track.

Uses: POST /api/v1/bom (multipart/form-data)
- Either provide a project UUID (recommended), OR provide projectName/projectVersion (+ optional autoCreate).
- Optionally wait for BOM processing to complete by polling /api/v1/bom/token/{token}.

Docs:
- Upload examples + parameters: /api/v1/bom :contentReference[oaicite:1]{index=1}
- Token polling returns boolean while processing :contentReference[oaicite:2]{index=2}
- OpenAPI docs are available from the backend at /api/openapi.json :contentReference[oaicite:3]{index=3}
"""

from __future__ import annotations
from configuration import Configuration as Config
import json
import sys
import time
from pathlib import Path
from typing import Optional

import requests


def _normalize_base_url(url: str) -> str:
    # Accept things like "https://dtrack.example.com/" and normalize to "https://dtrack.example.com"
    return url.strip().rstrip("/")


def _boolish(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _parse_processing_response(resp: requests.Response) -> bool:
    """
    /api/v1/bom/token/{token} is commonly a boolean response.
    Be tolerant in case it's JSON true/false, plain text, or a small object.
    """
    # Try JSON first
    try:
        j = resp.json()
        if isinstance(j, bool):
            return j
        if isinstance(j, dict):
            # Some APIs wrap booleans; try common keys.
            for key in ("processing", "isProcessing", "inProgress", "value"):
                if key in j and isinstance(j[key], bool):
                    return j[key]
            # If dict but unknown shape, fall back to string conversion
            return _boolish(json.dumps(j))
        if isinstance(j, str):
            return _boolish(j)
    except Exception:
        pass

    # Fall back to raw text
    return _boolish(resp.text)


def upload_bom() -> str:
    """
    Upload SBOM and return the processing token (UUID-like string).
    """
    url = f"{_normalize_base_url(Config.dtrack_base_url)}/api/v1/bom"
    headers = {"X-Api-Key": Config.dtrack_api_key}

    # Multipart form fields
    data: dict[str, str] = {}

    if Config.dtrack_project_uuid:
        data["project"] = Config.dtrack_project_uuid
    else:
        # Alternative parameters (name/version + optional autoCreate)
        # Docs show these are supported :contentReference[oaicite:4]{index=4}
        if not (Config.dtrack_project_name and Config.dtrack_project_version):
            raise ValueError("You must specify either project-uuid OR both project-name and project-version.")

        data["projectName"] = Config.dtrack_project_name
        data["projectVersion"] = Config.dtrack_project_version
        if Config.dtrack_project_auto_create:
            data["autoCreate"] = "true"

        # Optional parent fields (supported per docs) :contentReference[oaicite:5]{index=5}
        if Config.dtrack_parent_project_uuid:
            data["parentUUID"] = Config.dtrack_parent_project_uuid
        if Config.dtrack_parent_project_name:
            data["parentName"] = Config.dtrack_parent_project_name
        if Config.dtrack_parent_project_version:
            data["parentVersion"] = Config.dtrack_parent_project_version

    if not Config.sbom_output_file_path.is_file():
        raise FileNotFoundError(f"SBOM file not found: {Config.sbom_output_file_path}")

    # Requests will set the correct multipart boundary; do NOT set Content-Type manually.
    with Config.sbom_output_file_path.open("rb") as f:
        files = {"bom": (Config.sbom_output_file_path.name, f, "application/octet-stream")}
        resp = requests.post(
            url,
            headers=headers,
            data=data,
            files=files,
            proxies=Config.proxies,
            verify=Config.dtrack_verify_tls,
            timeout=Config.dtrack_timeout,
        )

    if resp.status_code >= 400:
        # Try to print helpful server message
        body = resp.text.strip()
        raise RuntimeError(
            f"Upload failed: HTTP {resp.status_code} {resp.reason}\nResponse body:\n{body}"
        )

    # Expected response is JSON like {"token":"..."} in many setups
    try:
        j = resp.json()
        token = j.get("token") if isinstance(j, dict) else None
    except Exception:
        token = None

    if not token:
        # Fall back to raw response
        token = resp.text.strip().strip('"')

    if not token:
        raise RuntimeError(f"Upload succeeded (HTTP {resp.status_code}) but no token was returned. Body:\n{resp.text}")

    return token


def wait_for_processing(*, token: str,) -> None:
    """
    Poll /api/v1/bom/token/{token} until it returns false, or until max_wait_seconds is exceeded.

    Maintainers describe the endpoint as returning true while processing and false when complete. :contentReference[oaicite:6]{index=6}
    """
    url = f"{_normalize_base_url(Config.dtrack_base_url)}/api/v1/bom/token/{token}"
    headers = {"X-Api-Key": Config.dtrack_api_key}

    deadline = time.time() + Config.dtrack_max_wait
    while True:
        resp = requests.get(
            url,
            headers=headers,
            verify=Config.dtrack_verify_tls,
            timeout=Config.dtrack_timeout,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Token check failed: HTTP {resp.status_code} {resp.reason}\nResponse body:\n{resp.text}"
            )

        processing = _parse_processing_response(resp)
        if not processing:
            return

        if time.time() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for BOM processing to complete after {Config.dtrack_max_wait}s (token={token})."
            )

        time.sleep(Config.dtrack_poll_interval)



def main() -> None:
    if not Config.dtrack_api_key:
        print("ERROR: API key missing. Provide --api-key or set DTRACK_API_KEY.", file=sys.stderr)
        sys.exit()

    # TLS verify behavior:
    # - default: True
    # - if --ca-bundle: verify=<path>
    # - if --insecure: verify=False
    if Config.dtrack_insecure and Config.dtrack_ca_bundle:
        print("ERROR: Use either insecure OR ca-bundle, not both.", file=sys.stderr)
        sys.exit()

    verify_tls: bool | str = True
    if Config.dtrack_ca_bundle:
        Config.dtrack_verify_tls = str(Path(Config.dtrack_ca_bundle))
    elif Config.dtrack_insecure:
        Config.dtrack_verify_tls = False

    try:
        token = upload_bom()
        print(f"Upload accepted. Processing token: {token}")

        if Config.dtrack_max_wait:
            print("Waiting for Dependency-Track to finish processing the BOM...")
            wait_for_processing(token=token,)
            print("BOM processing complete.")


    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit()


if __name__ == "__main__":
    main()
