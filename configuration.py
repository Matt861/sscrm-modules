from root import get_project_root
import os
import utils
from pathlib import Path

p = Path(__file__).resolve()


class Configuration:
    # DIRECTORIES
    root_dir = get_project_root()
    input_dir = Path(root_dir, "input")
    output_dir = Path(root_dir, "output")
    cache_dir = Path(root_dir, "cache")
    log_dir = Path(root_dir, "logs")
    templates_dir = Path(root_dir, "templates")
    sbom_input_dir = Path(input_dir, "sbom_gen")
    project_output_dir = ""

    # PROJECT PROPERTIES
    project_name = ""
    project_version = ""
    package_manager = ""
    os_identification = ""
    is_deliverable_software = ""
    software_end_use = ""
    non_standard_file = ""
    is_executable = ""
    has_dependencies = ""
    execution_control_level = ""
    non_os_specific_packages = ["maven", "pypi", "npm"]
    executable_packages = ["raw"]

    # PROJECT SETUP
    #utils.load_env_vars(Path(root_dir, ".env"))
    utils.load_env_file(Path(root_dir, ".env"))
    crt_sscrm_github_tokens = utils.read_newline_list("CRT_SSCRM_GITHUB_TOKENS")

    # GITHUB METRICS PROPERTIES
    proxies = {"http": "", "https": ""}
    # crt_sscrm_github_tokens = []
    # crt_sscrm_github_token_1 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_1")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_1)
    # crt_sscrm_github_token_2 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_2")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_2)
    # crt_sscrm_github_token_3 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_3")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_3)
    # crt_sscrm_github_token_4 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_4")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_4)
    # crt_sscrm_github_token_5 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_5")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_5)
    # crt_sscrm_github_token_6 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_6")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_6)
    # crt_sscrm_github_token_7 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_7")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_7)
    # crt_sscrm_github_token_8 = os.getenv("CRT_SSCRM_GITHUB_TOKEN_8")
    # crt_sscrm_github_tokens.append(crt_sscrm_github_token_8)

    github_repository_store = None
    github_client = None
    github_perf_client = None
    gql_batch_size = 25
    github_api_base_url = "https://api.github.com"
    github_metrics_output_folder_name = "github_metrics"

    # CONTRIBUTOR METRICS PROPERTIES
    contributor_store = None
    max_contributors = 500
    max_profile_lookups = 500

    # GEOLOCATOR PROPERTIES
    nominatim_client = None
    nominatim_api_base_url = "https://nominatim.openstreetmap.org"

    # SBOM GEN PROPERTIES
    sbom_format = "json" #Choices: json, xml, all
    sbom_output_file_path = ""
    sbom_output_file_name = ""
    maven_sbom_input_file = "pom.xml"
    pypi_sbom_input_file = "requirements.txt"
    npm_sbom_input_file = "package.json"
    raw_sbom_input_file = "package.csv"
    sbom_input_file = ""
    cyclonedx_maven_plugin_version = "2.9.1"
    maven_command = "mvn.cmd"
    maven_skip_tests_flag = True
    maven_include_test_scope = False
    maven_offline_mode = False
    maven_goal = "makeAggregateBom" #Choices: makeAggregateBom, makeBom


    # SBOM PARSER PROPERTIES
    component_store = None
    sbom_parser_dedupe = True

    # FILE NAMES
    sis_csv_file_name = None
    gray_sis_pdf_file_name = None
    green_sis_xlsx_file_name = None
    components_csv_file_name = None
    no_repo_components_csv_file_name = None
    vuln_file_name = None
    github_metrics_file_name = "github-metrics.csv"
    sis_row_template_name = "sis_row_template.json"
    green_sis_row_template_name = "green_sis_row_template.json"
    gray_sis_template_name = "gray_sis_template_modified.pdf"
    component_row_template_name = "component_row_template.json"
    maven_sbom_gen_log_file_name = "maven_sbom_gen_subprocess.log"
    green_sis_xlsx_template_name = "green-sis-template-2026.xlsx"
    nominatim_cache_file_name = "nominatim_cache.json"

    # GRAY SIS PROPERTIES
    is_deliverable_checkbox = ""
    is_deliverable_radio_button = ""
    is_executable_radio_button = ""
    has_dependencies_radio_button = "/Are there any dependencies to othersoftware that a_No_On"

    # GREEN SIS PROPERTIES
    green_sis_xlsx_sheet_name = "SW Submissions"

    # DTRACK PROPERTIES
    dtrack_base_url = ""
    dtrack_api_key = ""
    dtrack_project_uuid = ""
    dtrack_project_name = ""
    dtrack_project_version = ""
    dtrack_project_auto_create = ""
    dtrack_verify_tls = ""
    dtrack_timeout_seconds = 0




