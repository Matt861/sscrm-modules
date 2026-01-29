# CLOSED_ISSUES_QUERY = """
# query ClosedIssueCount($owner: String!, $name: String!) {
#   repository(owner: $owner, name: $name) {
#     issues(states: CLOSED) { totalCount }
#   }
# }
# """

CLOSED_ISSUES_QUERY = """
query ClosedIssueCount($owner: String!, $name: String!) {
  rateLimit {
    cost
    remaining
    resetAt
  }
  repository(owner: $owner, name: $name) {
    issues(states: CLOSED) { totalCount }
  }
}
"""

REPO_METRICS_GQL = """
query RepoMetrics($owner: String!, $name: String!) {
  rateLimit {
    cost
    remaining
    resetAt
  }
  repository(owner: $owner, name: $name) {
    createdAt
    updatedAt
    stargazerCount
    forkCount
    releases {
      totalCount
    }
    refs(refPrefix: "refs/tags/") {
      totalCount
    }
    issues(states: CLOSED) {
      totalCount
    }
  }
}
"""

REPO_METRICS_FIELDS = """
createdAt
updatedAt
stargazerCount
forkCount
releases { totalCount }
refs(refPrefix: "refs/tags/") { totalCount }
issues(states: CLOSED) { totalCount }
"""