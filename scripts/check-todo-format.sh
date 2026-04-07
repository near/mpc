#!/usr/bin/env bash
set -euo pipefail

# Define extensions as an array for cleaner handling
CHECKED_EXTENSIONS=(
  "*.rs" "*.py" "*.sh" "*.yml" "*.yaml" "*.md"
)

# 1. git ls-files -z uses null-termination for space-safe filenames
# 2. xargs -0 reads those null-terminated strings
# 3. grep \btodo\b looks for the word "todo" specifically
# 4. The final grep -v -E filters out the two valid patterns
INVALID_TODOS=$(git ls-files -z "${CHECKED_EXTENSIONS[@]}" | \
    xargs -0 grep -HinE "\btodo\b" | \
    grep -vE ":.*(TODO\(#[0-9]+\):|TODO:)" || true)

# Files/patterns excluded from the check (contain "todo" in identifiers, not as TODO comments).
EXCLUDE_ARGS=(
    -e "check-todo-format"
    -e "check-todo-closed-issues"
    -e "CHANGELOG.md"
)
INVALID_TODOS=$(echo "$INVALID_TODOS" | grep -vF "${EXCLUDE_ARGS[@]}" || true)

if [ -n "$INVALID_TODOS" ]; then
    echo "❌ Found TODO comments not matching the required format"
    echo ""
    echo "Valid formats:"
    echo "  TODO(#1234): description"
    echo "  TODO: description"
    echo ""
    echo "Invalid lines found:"
    echo "$INVALID_TODOS"
    exit 1
fi

echo "✅ All TODO comments follow the required format"
exit 0