from artifact_generators import sis_gen, components_gen
from artifact_generators.github_metrics_gen import write_repo_json_files
from artifact_generators.repo_metrics_gen import write_repo_store_to_csv
from configuration import Configuration as Config
from sbom_generators import sbom_gen
from timer import Timer
from loggers.main_logger import main_logger as logger
from pathlib import Path
from repo_metrics import analysis, geolocator
from repo_metrics.github import github_metrics, contributor_metrics
from tools import sbom_parser, repo_url_finder

p = Path(__file__).resolve()

main_timer = Timer()
main_timer.start("starting main timer")


def main() -> None:
    Config.project_name = "crt-service-1.0.0"
    Config.package_manager = "maven"
    Config.software_type = Config.package_manager
    Config.sbom_gen_input_dir = Path(Config.root_dir, "input/sbom_gen/crt/crt-service")
    Config.sbom_gen_input_file = "input/sbom_gen/crt/crt-service/pom.xml"
    Config.sbom_gen_output_dir = "output/sboms"
    Config.sbom_gen_output_file = "crt-service-1.0.0-sbom"

    # ADD LOGIC TO SET PROPERTY "IS_SOFTWARE_DELIVERABLE" BASED ON USER INPUT (DELIVERABLE, TEST/DEV, BUILD/CLASSPATH)

    # ADD LOGIC TO SET PROPERTY "SOFTWARE_END_USE" BASED ON USER INPUT (DELIVERABLE, TEST/DEV, BUILD/CLASSPATH)

    # ADD LOGIC TO SET NON_STANDARD_FILE

    sbom_gen_timer = Timer()
    sbom_gen_timer.start("starting sbom_gen timer")
    sbom_gen.main()
    sbom_gen_timer.stop("stopping sbom_gen timer")
    print(logger.info(sbom_gen_timer.elapsed("Elapsed time for sbom_gen: ")))

    sbom_parser_timer = Timer()
    sbom_parser_timer.start("starting sbom_parser timer")
    sbom_parser.main()
    sbom_parser_timer.stop("stopping sbom_parser timer")
    print(logger.info(sbom_parser_timer.elapsed("Elapsed time for sbom_parser: ")))

    repo_url_finder_timer = Timer()
    repo_url_finder_timer.start("starting repo_url_finder timer")
    repo_url_finder.main()
    repo_url_finder_timer.stop("stopping repo_url_finder timer")
    print(logger.info(repo_url_finder_timer.elapsed("Elapsed time for repo_url_finder: ")))

    github_metrics_timer = Timer()
    github_metrics_timer.start("starting github_metrics timer")
    github_metrics.main()
    github_metrics_timer.stop("stopping github_metrics timer")
    print(logger.info(github_metrics_timer.elapsed("Elapsed time for github_metrics: ")))

    contributor_metrics_timer = Timer()
    contributor_metrics_timer.start("starting contributor_metrics timer")
    contributor_metrics.main()
    contributor_metrics_timer.stop("stopping contributor_metrics timer")
    print(logger.info(contributor_metrics_timer.elapsed("Elapsed time for contributor_metrics: ")))

    geolocator_timer = Timer()
    geolocator_timer.start("starting geolocator timer")
    geolocator.main()
    geolocator_timer.stop("stopping geolocator timer")
    print(logger.info(geolocator_timer.elapsed("Elapsed time for geolocator: ")))

    analysis.calculate_repo_scores()
    csv_out = Path(Config.root_dir, "output/githubmetrics.csv")
    write_repo_store_to_csv(Config.github_repository_store, csv_out, overwrite=True)
    print(f"Wrote CSV to: {csv_out}")
    output_paths = write_repo_json_files(repos=Config.github_repository_store.get_all(), output_dir=Path(Config.root_dir, "output/githubmetrics"))
    print("Wrote", len(output_paths), "files")

    sis_gen.main()
    components_gen.main()

    # github_repos = Config.github_repository_store.get_all()
    # if github_repos:
    #     for github_repo in github_repos:
    #         print(github_repo.repo_url, github_repo.releases_count, github_repo.tags_count, github_repo.stars,
    #               github_repo.forks, github_repo.closed_issues_count, len(github_repo.contributors))
    #         repo_scores = github_repo.repo_scores
    #         if repo_scores:
    #             print(repo_scores.stars_score, repo_scores.forks_score, repo_scores.prevalence_score,
    #                   repo_scores.maturity_score, repo_scores.last_updated_score, repo_scores.trusted_org_bonus,
    #                   repo_scores.unclass_score, repo_scores.passes_sia)
    #         print()
    #
    # Config.github_perf_client.pool.print_gql_token_stats()
    print('done')


if __name__ == "__main__":
    main()
    main_timer.stop("stopping main timer")
    print(logger.info(main_timer.elapsed("Elapsed time for main: ")))