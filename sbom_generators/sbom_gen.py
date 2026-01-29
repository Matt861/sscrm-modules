import sys

from configuration import Configuration as Config
from sbom_generators import maven_sbom_gen


def main() -> None:
    if Config.package_manager.lower() == "maven":
        maven_sbom_gen.main()
    elif Config.package_manager.lower() == "pypi":
        print('to do')
    elif Config.package_manager.lower() == "npm":
        print('to do')
    elif Config.package_manager.lower() == "raw":
        print('to do')
    else:
        sys.exit("Invalid package manager type provided.")





if __name__ == "__main__":
    Config.package_manager = "maven"
    main()