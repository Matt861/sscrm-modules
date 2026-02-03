from __future__ import annotations

import copy
import re
from typing import Optional
from urllib.parse import urlparse

from configuration import Configuration as Config
from datetime import datetime, timezone
import utils
import csv
from pathlib import Path

non_os_specific_packages = ["maven", "pypi", "npm"]
executable_packages = ["raw"]

def get_trusted_org(github_url):
    trusted_orgs_data = utils.load_json_file(Path(Config.root_dir, 'input/trusted_orgs.json'))
    trusted_orgs = trusted_orgs_data.keys()
    component_org = urlparse(github_url).path.strip('/').split('/')[0]
    for trusted_org in trusted_orgs:
        if component_org.lower() == trusted_org.lower():
            return trusted_org
    return ''


def get_os_identification():
    if Config.package_manager.lower() in non_os_specific_packages:
        return "N/A"
    elif Config.os_identification:
        return Config.os_identification
    else:
        return ""


def is_package_executable():
    if Config.package_manager.lower() in executable_packages:
        return True
    else:
        return False


def get_github_publisher_from_url(url: str) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None

    s = url.strip()

    # Handle SSH form: git@github.com:OWNER/REPO(.git)
    m = re.match(r"^(?:ssh://)?git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$", s, re.IGNORECASE)
    if m:
        return m.group("owner")

    # Add scheme if missing so urlparse works correctly
    if "://" not in s:
        s = "https://" + s

    parsed = urlparse(s)

    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").strip("/")

    # Common GitHub hosts that still encode owner/repo in the path
    # - github.com/OWNER/REPO
    # - raw.githubusercontent.com/OWNER/REPO/...
    if host in {"github.com", "www.github.com", "raw.githubusercontent.com"}:
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            owner = parts[0]
            # Basic sanity: owner can't be "." or ".."
            if owner not in {".", ".."}:
                return owner

    return ""


def get_publisher(component):
    if component.publisher:
        return component.publisher
    elif component.repo_url:
        return get_github_publisher_from_url(component.repo_url)
    else:
        return ""


def days_from_date_to_now(date_str: str) -> int:
    """
    Takes a date like "2025-11-27T11:26:02Z" (UTC) and returns the number of days
    from that date to *now* (UTC), rounded to the nearest int.

    Positive => date is in the past (days since)
    Negative => date is in the future (days until)
    """
    # Parse ISO-8601 with trailing 'Z' (UTC)
    dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta_days = (now - dt).total_seconds() / 86400.0  # seconds per day

    return int(round(delta_days))


def hours_from_date_to_now(date_str: str) -> int:
    """
    Takes a date like "2025-11-27T11:26:02Z" (UTC) and returns the number of hours
    from that date to *now* (UTC), rounded to the nearest int.

    Positive => date is in the past (hours since)
    Negative => date is in the future (hours until)
    """
    dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta_hours = (now - dt).total_seconds() / 3600.0  # seconds per hour

    return int(round(delta_hours))


def append_component_info(component, csv_row):
    csv_row['Package'] = component.name
    csv_row['Version'] = component.version
    csv_row['Group'] = component.group
    csv_row['Is_Direct'] = component.is_direct
    csv_row['Description'] = component.description
    csv_row['Publisher'] = get_publisher(component)
    csv_row['Is_Latest_Version'] = ""
    csv_row['Vulnerabilities'] = ""
    csv_row['Critical_or_High'] = ""


def append_repo_metrics(repo_data, csv_row):
    csv_row['Stars'] = repo_data.stars
    csv_row['Forks'] = repo_data.forks
    csv_row['Closed_Issues'] = repo_data.closed_issues_count
    csv_row['Releases'] = repo_data.releases_count
    csv_row['Tags'] = repo_data.tags_count
    csv_row['Age_Days'] = days_from_date_to_now(repo_data.created_at)
    csv_row['Last_Update_Hours'] = hours_from_date_to_now(repo_data.updated_at)
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
    csv_row['Is_Executable'] = str(is_package_executable())
    csv_row['Non_Standard_File'] = str(Config.non_standard_file)
    csv_row['OS_Identification'] = get_os_identification()
    csv_row['Used_On_Deliverable'] = str(Config.is_deliverable_software)
    csv_row['End_Use'] = Config.software_end_use
    csv_row['Software_Type'] = Config.software_type



def append_efoss_info(efoss_data, csv_row):
    #csv_row['License Status'] = efoss_data.get('approvalStatus', '')
    csv_row['eFOSS_Status'] = ''


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
    Config.sis_csv_file_name = f"{Config.project_name}-{Config.project_version}-sis.csv"
    sis_csv_path = Path(Config.root_dir, "output", Config.sis_csv_file_name)
    generate_sis_csv(sis_csv_path)



if __name__ == "__main__":
    main()

