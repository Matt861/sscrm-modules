from artifact_generators import sis_gen, components_gen, gray_sis_gen, no_repo_components_gen, green_sis_gen, \
    repo_metrics_gen, github_metrics_gen
from configuration import Configuration as Config
from dtrack import dtrack_post_api, dtrack_get_api
from dtrack.dtrack_client import DependencyTrackClient
from sbom_generators import sbom_gen
from timer import Timer
from loggers.main_logger import main_logger as logger
from pathlib import Path
from repo_metrics import analysis, geolocator
from repo_metrics.github import github_metrics, contributor_metrics
from tools import sbom_parser, repo_url_finder, sis_value_setter

p = Path(__file__).resolve()

main_timer = Timer()
main_timer.start("starting main timer")


def main() -> None:
    Config.project_name = "npm-test"
    Config.project_version = "1.0.3"
    Config.package_manager = "npm"
    Config.software_end_use = "DELIVERABLE"
    #Config.sbom_input_dir = Path(Config.input_dir, "sbom_gen/crt/crt-service")
    Config.project_output_dir = Path(Config.output_dir, f"{Config.project_name}-{Config.project_version}")
    Config.project_output_dir.mkdir(parents=True, exist_ok=True)



    sbom_gen_timer = Timer()
    sbom_gen_timer.start("starting sbom_gen timer")
    sbom_gen.main()
    sbom_gen_timer.stop("stopping sbom_gen timer")
    print(logger.info(sbom_gen_timer.elapsed("Elapsed time for sbom_gen: ")))

    sbom_parser_timer = Timer()
    sbom_parser_timer.start("starting sbom_parser timer")
    sbom_parser.main()
    sbom_parser_timer.stop("stopping sbom_parser timer")
    logger.info(sbom_parser_timer.elapsed("Elapsed time for sbom_parser: "))

    # repo_url_finder_timer = Timer()
    # repo_url_finder_timer.start("starting repo_url_finder timer")
    # repo_url_finder.main()
    # repo_url_finder_timer.stop("stopping repo_url_finder timer")
    # logger.info(repo_url_finder_timer.elapsed("Elapsed time for repo_url_finder: "))

    github_metrics_timer = Timer()
    github_metrics_timer.start("starting github_metrics timer")
    github_metrics.main()
    github_metrics_timer.stop("stopping github_metrics timer")
    logger.info(github_metrics_timer.elapsed("Elapsed time for github_metrics: "))

    contributor_metrics_timer = Timer()
    contributor_metrics_timer.start("starting contributor_metrics timer")
    contributor_metrics.main()
    contributor_metrics_timer.stop("stopping contributor_metrics timer")
    logger.info(contributor_metrics_timer.elapsed("Elapsed time for contributor_metrics: "))

    geolocator_timer = Timer()
    geolocator_timer.start("starting geolocator timer")
    geolocator.main()
    geolocator_timer.stop("stopping geolocator timer")
    logger.info(geolocator_timer.elapsed("Elapsed time for geolocator: "))

    repo_scores_timer = Timer()
    repo_scores_timer.start("starting repo scores timer")
    analysis.main()
    repo_scores_timer.stop("stopping repo scores timer")
    logger.info(repo_scores_timer.elapsed("Elapsed time for repo scores: "))

    #Config.dtrack_client = DependencyTrackClient()
    #dtrack_post_api.main()
    #dtrack_get_api.main()

    file_gen_timer = Timer()
    file_gen_timer.start("starting file gen timer")
    repo_metrics_gen.main()
    github_metrics_gen.main()
    sis_value_setter.main()
    sis_gen.main()
    components_gen.main()
    no_repo_components_gen.main()
    green_sis_gen.main()
    gray_sis_gen.main()
    file_gen_timer.stop("stopping file gen timer")
    logger.info(file_gen_timer.elapsed("Elapsed time for file gen: "))


    Config.github_perf_client.pool.print_gql_token_stats()



if __name__ == "__main__":
    main()
    main_timer.stop("stopping main timer")
    logger.info(main_timer.elapsed("Elapsed time for main: "))