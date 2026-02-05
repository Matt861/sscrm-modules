import requests

from configuration import Configuration as Config
import mimetypes
import os
from typing import Dict, Any, Optional

from dtrack.dtrack_client import DependencyTrackClient


def upload_sbom(
        self,
        sbom_path: Optional[str] = None,
        sbom_content: Optional[str] = None,
        project_uuid: Optional[str] = None,
        auto_create: bool = False,
        classifier: Optional[str] = None,
        content_type: Optional[str] = None,
        filename: Optional[str] = None,
) -> Any:
    """
    Upload an SBOM (BOM) to Dependency-Track.

    Parameters:
    - sbom_path: path to the SBOM file to upload (mutually exclusive with sbom_content)
    - sbom_content: SBOM content as a string/bytes (mutually exclusive with sbom_path)
    - project_uuid: optional project UUID to associate the BOM with
    - auto_create: if True, allow creating the project automatically when project_uuid is not provided
    - content_type: optional explicit content type (e.g., "application/json", "application/xml", "text/xml")
    - filename: optional filename to send for the uploaded file (defaults to basename of sbom_path or "bom.xml"/"bom.json")

    Returns:
    - Parsed JSON response from the server if any, or None for empty responses.

    Notes:
    Dependency-Track commonly exposes POST /api/v1/bom which accepts a multipart/form-data upload
    with the file field named 'bom'. Query parameters like 'project' and 'autoCreate' are supported.
    """
    if (sbom_path and sbom_content) or (not sbom_path and sbom_content is None):
        raise ValueError("Provide exactly one of sbom_path or sbom_content")

    if sbom_path:
        if not os.path.isfile(sbom_path):
            raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
        with open(sbom_path, "rb") as f:
            sbom_bytes = f.read()
        if not filename:
            filename = os.path.basename(sbom_path)
        if not content_type:
            content_type, _ = mimetypes.guess_type(sbom_path)
    else:
        # sbom_content provided
        if isinstance(sbom_content, str):
            sbom_bytes = sbom_content.encode("utf-8")
        elif isinstance(sbom_content, bytes):
            sbom_bytes = sbom_content
        else:
            raise TypeError("sbom_content must be str or bytes")
        if not filename:
            # try to guess from content (default to bom.json)
            filename = "bom.json" if (content_type and "json" in content_type) else "bom.xml"
        if not content_type:
            # default guesses
            content_type = "application/json" if filename.endswith(".json") else "application/xml"

    if not content_type:
        # final fallback
        content_type = "application/octet-stream"

    params: Dict[str, Any] = {}
    if project_uuid:
        params["project"] = project_uuid
    if auto_create:
        # API expects true/false; send as lowercase string
        params["autoCreate"] = str(bool(auto_create)).lower()
    if classifier:
        params["classifier"] = classifier

    files = {"bom": (filename, sbom_bytes, content_type)}

    url = self._url("/bom")
    resp = self.session.post(url, params=params, files=files, timeout=self.timeout, verify=self.verify)
    resp.raise_for_status()
    if resp.content:
        # Many endpoints return JSON details about processing
        try:
            return resp.json()
        except ValueError:
            # Not JSON, return raw text
            return resp.text
    return None


def main() -> None:
    if not Config.dtrack_api_key:
        raise SystemExit("ERROR: Dependency-Track API key missing.")

    # Example: upload an SBOM file and optionally associate it with a project UUID
    sbom_file_path = Config.sbom_output_file_path  # path to your CycloneDX or SPDX BOM file
    project_uuid = Config.dtrack_project_uuid  # or set to a project UUID to attach the BOM
    auto_create = Config.dtrack_project_auto_create
    classifier = Config.dtrack_classifier

    try:
        result = Config.dtrack_client.upload_sbom(sbom_path=sbom_file_path, project_uuid=project_uuid,
                                                  auto_create=auto_create, classifer=classifier)
        print("Upload result:")
        print(result)
    except requests.HTTPError as e:
        print(f"HTTP error during upload: {e} - response: {getattr(e.response, 'text', None)}")
    except Exception as e:
        print(f"Error during upload: {e}")


if __name__ == "__main__":
    Config.dtrack_client = DependencyTrackClient()
    main()