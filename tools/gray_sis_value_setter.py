from configuration import Configuration as Config
from models import enums


def main() -> None:
    member = enums.SoftwareType.__members__.get(Config.software_end_use.upper())
    if member is not None:
        if member.value is True:
            Config.is_deliverable_radio_button = "/Will software be used to develop adeliverable prod_Yes_On"
            Config.is_deliverable_checkbox = "/On"
        elif member.value is False:
            Config.is_deliverable_radio_button = "/Will software be used to develop adeliverable prod_No_On"


    member = enums.ExecutableSoftware.__members__.get(Config.package_manager.upper())
    if member is not None:
        if member.value is True:
            Config.is_executable = "/_No_On"
        elif member.value is False:
            Config.is_executable = "/_Yes_On"

    if Config.component_store:
        for component in Config.component_store.get_all_components():
            if not component.is_direct:
                Config.has_dependencies = True
                Config.has_dependencies_radio_button = "/Are there any dependencies to othersoftware that a_Yes If Yes identify and explain below Attach s"
                break



if __name__ == "__main__":
    main()