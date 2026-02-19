import sys

from configuration import Configuration as Config
from sbom_generators import maven_sbom_gen, pypi_sbom_gen, pypi_sbom_gen2, pypi_sbom_gen3, pypi_sbom_gen4, go_sbom_gen, \
    npm_sbom_gen, npm_sbom_gen2


def main() -> None:
    if Config.package_manager.lower() == "maven":
        Config.sbom_input_file = Config.sbom_input_file if Config.sbom_input_file else Config.maven_sbom_input_file
        maven_sbom_gen.main()
    elif Config.package_manager.lower() == "pypi":
        Config.sbom_input_file = Config.sbom_input_file if Config.sbom_input_file else Config.pypi_sbom_input_file
        pypi_sbom_gen4.main()
    elif Config.package_manager.lower() == "npm":
        Config.sbom_input_file = Config.sbom_input_file if Config.sbom_input_file else Config.npm_sbom_input_file
        npm_sbom_gen2.main()
    elif Config.package_manager.lower() == "go":
        Config.sbom_input_file = Config.sbom_input_file if Config.sbom_input_file else Config.go_sbom_input_file
        go_sbom_gen.main()
    elif Config.package_manager.lower() == "raw":
        Config.sbom_input_file = Config.sbom_input_file if Config.sbom_input_file else Config.raw_sbom_input_file
        print('to do')
    else:
        sys.exit("Invalid package manager type provided.")


if __name__ == "__main__":
    Config.package_manager = "maven"
    main()