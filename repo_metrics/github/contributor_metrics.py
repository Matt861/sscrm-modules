from configuration import Configuration as Config
from models.contributor import ContributorStore


def get_repo_contributors(github_repo):
    contributors = Config.github_perf_client.list_contributors(github_repo.owner, github_repo.name, fetch_profiles=True)
    github_repo.contributors = contributors
    Config.contributor_store.add_many(contributors)


def main():
    Config.contributor_store = ContributorStore()
    github_repos = Config.github_repository_store.get_all()
    if github_repos:
        for github_repo in github_repos:
            print(f"Fetching contributors for {github_repo.repo_url}")
            get_repo_contributors(github_repo)


if __name__ == "__main__":
    main()