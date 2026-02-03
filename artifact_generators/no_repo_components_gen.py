import copy
import csv
from pathlib import Path
import utils
from configuration import Configuration as Config


def generate_no_repo_components_csv(no_repo_components_csv_path):
    try:
        component_row_template = utils.load_json_file(Path(Config.root_dir, 'templates/component_row_template.json'))
        fieldnames = component_row_template.keys()
        rows = []
        with open(no_repo_components_csv_path, 'w', newline='', encoding="utf-8") as components_csv:
            writer = csv.DictWriter(components_csv, fieldnames=fieldnames)
            writer.writeheader()
            for component in Config.component_store.get_all_components():
                if not component.repo_url:
                    csv_row = copy.deepcopy(component_row_template)
                    csv_row['Component'] = component.name
                    csv_row['Version'] = component.version
                    csv_row['Group'] = component.group
                    csv_row['Is_Direct'] = str(component.is_direct)
                    csv_row['License'] = component.licenses
                    csv_row['Vulnerabilities'] = ""
                    rows.append(csv_row)

            for row in rows:
                writer.writerow(row)

        print(f"Successfully generated file: {no_repo_components_csv_path}")

    except (FileNotFoundError, IOError) as file_err:
        print(f"File error occurred: {file_err}")
    except KeyError as key_err:
        print(f"Key error occurred: {key_err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def main():
    Config.no_repo_components_csv_file_name = f"{Config.project_name}-{Config.project_version}-no-repo-components.csv"
    no_repo_components_csv_path = Path(Config.root_dir, "output", Config.no_repo_components_csv_file_name)
    generate_no_repo_components_csv(no_repo_components_csv_path)



if __name__ == "__main__":
    main()
