from __future__ import annotations

import copy
from urllib.parse import urlparse

from configuration import Configuration as Config
import utils
import csv
from pathlib import Path


def get_trusted_org(github_url):
    trusted_orgs_data = utils.load_json_file(Path(Config.root_dir, 'input/trusted_orgs.json'))
    trusted_orgs = trusted_orgs_data.keys()
    component_org = urlparse(github_url).path.strip('/').split('/')[0]
    for trusted_org in trusted_orgs:
        if component_org.lower() == trusted_org.lower():
            return trusted_org
    return ''


def append_component_info(component, csv_row):
    csv_row['Package'] = component.name
    csv_row['Version'] = component.version
    csv_row['Group'] = component.group
    csv_row['Description'] = component.description
    csv_row['Publisher'] = component.publisher
    csv_row['Is_Latest_Version'] = ""
    csv_row['Vulnerabilities'] = ""
    csv_row['Critical_or_High'] = ""


def append_repo_metrics(repo_data, csv_row):
    csv_row['Stars'] = repo_data.stars
    csv_row['Forks'] = repo_data.forks
    csv_row['Closed_Issues'] = repo_data.closed_issues_count
    csv_row['Releases'] = repo_data.releases_count
    csv_row['Age_Days'] = repo_data.created_at
    csv_row['Last_Update_Hours'] = repo_data.updated_at
    csv_row['Repo_URL'] = repo_data.repo_url
    csv_row['Trusted_Orgs'] = get_trusted_org(repo_data.repo_url)
    csv_row['SIA_Scan_ID'] = repo_data.retrieval_uuid
    csv_row['SIA_Scan_Date'] = repo_data.retrieved_at


def append_repo_scores(repo_scores, csv_row):
    csv_row['Stars_Score'] = repo_scores.stars_score
    csv_row['Forks_Score'] = repo_scores.forks_score
    csv_row['Prevalence_Score'] = repo_scores.prevalence_score
    csv_row['Maturity_Score'] = repo_scores.maturity_score
    csv_row['Last_Update_Score'] = repo_scores.last_updated_score
    csv_row['Trusted_Org_Bonus'] = repo_scores.trusted_org_bonus
    csv_row['Unclass_Total'] = repo_scores.unclass_score
    csv_row['Passes_SIA'] = repo_scores.passes_sia


def append_sis_info(component, csv_row):
    csv_row['Prev_Approved_Versions'] = ""
    csv_row['Is_Executable'] = ""
    csv_row['Non_Standard_File'] = ""


def append_efoss_info(efoss_data, csv_row):
    #csv_row['License Status'] = efoss_data.get('approvalStatus', '')
    csv_row['License Status'] = ''


def generate_sis_csv(sis_csv_path):
    try:
        sis_row_template = utils.load_json_file(Path(Config.root_dir, 'templates/sis_row_template.json'))
        fieldnames = sis_row_template.keys()
        rows = []
        with open(sis_csv_path, 'w', newline='', encoding="utf-8") as sis_csv:
            writer = csv.DictWriter(sis_csv, fieldnames=fieldnames)
            writer.writeheader()
            for component in Config.component_store.get_all_components():
                csv_row = copy.deepcopy(sis_row_template)
                repo_data = component.repo_info
                #efoss_data = EfossApi.run("get_record", component)
                append_sis_info(component, csv_row)
                append_component_info(component, csv_row)
                if repo_data:
                    append_repo_metrics(repo_data, csv_row)
                    repo_scores = repo_data.repo_scores
                    if repo_scores:
                        append_repo_scores(repo_scores, csv_row)
                # if efoss_data:
                #     append_efoss_info(efoss_data, csv_row)
                rows.append(csv_row)

            for row in rows:
                writer.writerow(row)

        print(f"Successfully generated file: {sis_csv_path}")

    except (FileNotFoundError, IOError) as file_err:
        print(f"File error occurred: {file_err}")
    except KeyError as key_err:
        print(f"Key error occurred: {key_err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def main():
    sis_csv_name = f"{Config.project_name}-sis.csv"
    sis_csv_path = Path(Config.root_dir, "output", sis_csv_name)
    generate_sis_csv(sis_csv_path)



if __name__ == "__main__":
    main()

