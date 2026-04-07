#!/usr/bin/env bash
set -euo pipefail

# Check that TODO(#NNN) comments don't reference closed GitHub issues.
# Non-blocking: exits 1 on stale TODOs, but CI uses continue-on-error so it
# shows as a yellow warning. Closing an issue externally shouldn't break CI.

OWNER="near"
REPO="mpc"
EXCLUDE_PATTERNS=(
    'check-todo-format\.sh'
)

# Extract unique issue numbers from TODO(#NNN) comments across all tracked files.
EXCLUDE_REGEX=$(IFS='|'; echo "${EXCLUDE_PATTERNS[*]}")
ISSUE_NUMBERS=$(git ls-files -z | grep -zvE "$EXCLUDE_REGEX" | \
    xargs -0 grep -hoE 'TODO\(#[0-9]+\)' 2>/dev/null | \
    grep -oE '[0-9]+' | sort -un || true)

if [ -z "$ISSUE_NUMBERS" ]; then
    echo "✅ No TODO(#NNN) references found"
    exit 0
fi

TOTAL=$(echo "$ISSUE_NUMBERS" | wc -l | tr -d ' ')
echo "Checking $TOTAL referenced issues against $OWNER/$REPO..."

# Batch all issue numbers into a single GraphQL query.
FIELDS=""
for num in $ISSUE_NUMBERS; do
    FIELDS="$FIELDS i_${num}: issue(number: $num) { number state }"
done

# gh exits non-zero on partial GraphQL errors (e.g. NOT_FOUND for PR numbers),
# but still returns valid data for resolved issues.
RAW=$(gh api graphql \
    --raw-field "query={ repository(owner: \"$OWNER\", name: \"$REPO\") { $FIELDS } }" \
    2>/dev/null) || true

if [ -z "$RAW" ]; then
    echo "⚠️  GitHub API query failed. Ensure gh is authenticated: gh auth status"
    exit 1
fi

CLOSED=$(echo "$RAW" | \
    jq -r '.data.repository | to_entries[] | select(.value != null and .value.state == "CLOSED") | .value.number' \
    2>/dev/null) || true

if [ -z "$CLOSED" ]; then
    echo "✅ All TODO(#NNN) references point to open issues"
    exit 0
fi

echo ""
echo "❌ Found TODO comments referencing closed issues:"
echo ""

for num in $CLOSED; do
    echo "  #${num} (closed):"
    # Print all file:line locations containing this TODO reference.
    git ls-files -z | \
        xargs -0 grep -Hn "TODO(#${num})" 2>/dev/null | sed 's/^/    /' || true
    echo ""
done

echo "Please remove or update these TODOs — the referenced issues are already closed."
echo "If the TODO is still relevant, open a new issue and update the reference."
exit 1
