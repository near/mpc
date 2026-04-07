#!/usr/bin/env bash
set -euo pipefail

# PR-focused check: when a PR claims to close issue #Y, verify that no
# TODO(#Y) comments remain in the codebase.

REPO_SLUG="${GITHUB_REPOSITORY:-near/mpc}"
OWNER="${REPO_SLUG%%/*}"
REPO="${REPO_SLUG#*/}"

# Determine PR number
PR_NUMBER="${PR_NUMBER:-}"
if [[ -z "$PR_NUMBER" ]]; then
    # GITHUB_REF is "refs/pull/<number>/merge" on pull_request events.
    PR_NUMBER=$(echo "${GITHUB_REF:-}" | grep -oE 'refs/pull/([0-9]+)/' | grep -oE '[0-9]+' || true)
fi

if [[ -z "$PR_NUMBER" ]]; then
    echo "Could not determine PR number. Skipping TODO check."
    exit 0
fi

# Query closing issues via GraphQL
QUERY='query($owner: String!, $repo: String!, $pr: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $pr) {
      closingIssuesReferences(first: 50) {
        nodes { number }
      }
    }
  }
}'

CLOSING_ISSUES_JSON=$(gh api graphql \
    -F owner="$OWNER" \
    -F repo="$REPO" \
    -F pr="$PR_NUMBER" \
    -f query="$QUERY")

# Extract issue numbers from closingIssuesReferences (captures both body
# keywords like Closes/Fixes/Resolves and manually linked issues)
if ! ALL_ISSUES=$(echo "$CLOSING_ISSUES_JSON" | jq -r \
    '.data.repository.pullRequest.closingIssuesReferences.nodes[].number' \
    | sort -un); then
    echo "Failed to parse GitHub API response"
    exit 1
fi

if [[ -z "$ALL_ISSUES" ]]; then
    echo "PR #$PR_NUMBER does not close any issues. Skipping TODO check."
    exit 0
fi

echo "PR #$PR_NUMBER closes issues: $(echo "$ALL_ISSUES" | tr '\n' ' ')"

# Check for remaining TODO(#NNN) references
FOUND_STALE=0
for issue_num in $ALL_ISSUES; do
    MATCHES=$(git ls-files | xargs grep -Hn "TODO(#${issue_num})" 2>/dev/null || true)
    if [[ -n "$MATCHES" ]]; then
        if [[ $FOUND_STALE -eq 0 ]]; then
            echo ""
            echo "❌ Found TODO comments for issues this PR closes:"
            echo ""
        fi
        echo "  TODO(#${issue_num}):"
        echo "$MATCHES" | sed 's/^/    /'
        echo ""
        FOUND_STALE=1
    fi
done

if [[ $FOUND_STALE -eq 1 ]]; then
    echo "This PR closes the above issues but leaves TODO references behind."
    echo "Please remove or update these TODOs before merging."
    exit 1
fi

echo "✅ No stale TODOs found for the issues this PR closes."
exit 0
