#!/usr/bin/env bash
set -euo pipefail

# Fetches PR comments via GraphQL and formats them for Claude review.
#
# Required env vars: GH_TOKEN, PR_NUMBER, REPO_OWNER, REPO_NAME
# Outputs: /tmp/pr_comments_context.txt

QUERY='query($owner: String!, $repo: String!, $prNumber: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $prNumber) {
      comments(first: 100) {
        totalCount
        nodes {
          author { login }
          body
          createdAt
        }
      }
      reviewThreads(first: 100) {
        totalCount
        nodes {
          isResolved
          isOutdated
          path
          line
          comments(first: 50) {
            nodes {
              author { login }
              body
              createdAt
              diffHunk
            }
          }
        }
      }
      reviews(first: 50) {
        totalCount
        nodes {
          author { login }
          body
          state
          createdAt
        }
      }
    }
  }
}'

# Execute GraphQL query and check for errors
if ! COMMENTS_JSON=$(gh api graphql \
  -f query="$QUERY" \
  -f owner="$REPO_OWNER" \
  -f repo="$REPO_NAME" \
  -F prNumber="$PR_NUMBER"); then
  echo "Warning: Failed to fetch PR comments. Proceeding without comment context."
  echo "⚠️ Unable to fetch existing comments due to API error." > /tmp/pr_comments_context.txt
  exit 0
fi

# Format comments for Claude using external Python script
# Write to file instead of env var to avoid E2BIG on large PRs
if [ -n "$COMMENTS_JSON" ]; then
  echo "$COMMENTS_JSON" > /tmp/pr_comments_json.txt
  python3 "$(dirname "$0")/format_pr_comments.py" /tmp/pr_comments_json.txt > /tmp/pr_comments_context.txt
else
  echo "⚠️ No comments data to process." > /tmp/pr_comments_context.txt
  exit 0
fi
