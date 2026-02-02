from root import get_project_root
import os
import utils
from pathlib import Path

p = Path(__file__).resolve()


class Configuration:
    # PROJECT PROPERTIES
    root_dir = get_project_root()
    project_name = None
    project_version = None
    project_name_and_version = f"{project_name}-{project_version}"
    package_manager = None
    os_identification = ""
    is_deliverable_software = None
    software_end_use = None
    software_type = None
    non_standard_file = False
    is_executable = None

    # PROJECT SETUP
    utils.load_env_vars(Path(root_dir, ".env"))

    # GITHUB METRICS PROPERTIES
    proxies = {"http": "", "https": ""}
    crt_sscrm_github_tokens = []
    crt_sscrm_github_token_1 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_1")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_1)
    crt_sscrm_github_token_2 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_2")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_2)
    crt_sscrm_github_token_3 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_3")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_3)
    crt_sscrm_github_token_4 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_4")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_4)
    crt_sscrm_github_token_5 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_5")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_5)
    crt_sscrm_github_token_6 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_6")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_6)
    crt_sscrm_github_token_7 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_7")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_7)
    crt_sscrm_github_token_8 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_8")
    crt_sscrm_github_tokens.append(crt_sscrm_github_token_8)
    github_repository_store = None
    github_client = None
    github_perf_client = None
    gql_batch_size = 25

    # CONTRIBUTOR METRICS PROPERTIES
    contributor_store = None
    max_contributors = 500
    max_profile_lookups = 500

    # GEOLOCATOR PROPERTIES
    nominatim_client = None

    # SBOM GEN PROPERTIES
    sbom_gen_input_dir = None
    sbom_gen_input_file = None
    sbom_gen_output_dir = None
    sbom_gen_output_file = None
    sbom_extension = ".json"

    # SBOM PARSER PROPERTIES
    component_store = None

    # FILE NAMES
    sis_csv_file_name = None
    gray_sis_pdf_file_name = None
    green_sis_csv_file_name = None
    components_csv_file_name = None
    vuln_file_name = None

    # GRAY SIS VALUES
    is_deliverable_checkbox = None
    is_deliverable_radio_button = None

