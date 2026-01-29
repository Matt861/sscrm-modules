import constants
import utils
from configuration import Configuration as Config
import os
from urllib.parse import urlparse


def stars_score(stars):
    if stars < 5:
        return 0
    elif stars < 10:
        return 0.1
    elif stars < 25:
        return 0.2
    elif stars < 35:
        return 0.3
    elif stars < 45:
        return 0.4
    elif stars < 55:
        return 0.5
    elif stars < 65:
        return 0.6
    elif stars < 85:
        return 0.7
    elif stars < 95:
        return 0.8
    elif stars < 100:
        return 0.9
    elif stars >= 100:
        return 1.0


def forks_score(forks):
    if forks < 2:
        return 0
    elif forks < 3:
        return 0.1
    elif forks < 7:
        return 0.2
    elif forks < 10:
        return 0.3
    elif forks < 13:
        return 0.4
    elif forks < 17:
        return 0.5
    elif forks < 23:
        return 0.6
    elif forks < 30:
        return 0.7
    elif forks < 37:
        return 0.8
    elif forks >= 37:
        return 1.0


def maturity_score(maturity):
    if maturity < 0.25:
        return 0
    elif maturity < 0.5:
        return 0.2
    elif maturity < 1.0:
        return 0.4
    elif maturity < 2.0:
        return 0.6
    elif maturity < 3.0:
        return 0.8
    elif maturity < 4.0:
        return 0.9
    elif maturity >= 4.0:
        return 1.0


def last_updated_score(last_updated):
    if last_updated >= 3.0:
        return 0
    elif last_updated > 1.0:
        return 0.2
    elif last_updated > 0.5:
        return 0.4
    elif last_updated > 0.25:
        return 0.6
    elif last_updated > 0.10:
        return 0.8
    #elif last_updated <= 0.05:
    elif last_updated <= 0.10:
        return 1.0


def releases_score(releases):
    if releases == 0:
        return 0
    elif releases < 2:
        return 0.1
    elif releases < 3:
        return 0.2
    elif releases < 7:
        return 0.3
    elif releases < 13:
        return 0.4
    elif releases < 17:
        return 0.5
    elif releases < 20:
        return 0.6
    elif releases < 23:
        return 0.7
    elif releases < 27:
        return 0.8
    elif releases >= 27:
        return 1.0


def closed_issues_score(closed_issues):
    if closed_issues == 0:
        return 0
    elif closed_issues < 7:
        return 0.1
    elif closed_issues < 17:
        return 0.2
    elif closed_issues < 33:
        return 0.3
    elif closed_issues < 50:
        return 0.4
    elif closed_issues < 100:
        return 0.6
    elif closed_issues < 133:
        return 0.8
    elif closed_issues < 167:
        return 0.9
    elif closed_issues >= 167:
        return 1.0


def trusted_org_bonus(github_url):
    trusted_orgs_data = utils.load_json_file(os.path.join(Config.root_dir, 'input/trusted_orgs.json'))
    trusted_orgs = trusted_orgs_data.keys()
    component_org = urlparse(github_url).path.strip('/').split('/')[0]
    for trusted_org in trusted_orgs:
        if component_org.lower() == trusted_org.lower():
            return constants.BONUS_ORG_WEIGHT
    return 0


# def trusted_org_bonus(component, trusted_orgs):
#     if component.get_repo_owner():
#         if component.get_repo_owner().lower() in trusted_orgs:
#             component.set_trusted_org(trusted_orgs[component.get_repo_owner()])
#             return 10
#     return 0
