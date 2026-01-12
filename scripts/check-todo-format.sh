#!/usr/bin/env bash
# Check that all TODO comments follow one of these formats:
# - TODO(#NNN): description (with issue reference)
# - TODO: description (without issue reference)
# This enforces uppercase TODO and proper formatting.

set -euo pipefail

CHECKED_FILE_EXTENSIONS="*.rs *.py *.sh *.yml *.yaml *.md"

# Use git ls-files to respect .gitignore and exclude submodules.
# Find all TODO comments (case-insensitive), then filter out valid patterns.
# Exclude check-todo-format.sh and todo-format-check.yml (they mention
# "todo-format" in descriptions).
INVALID_TODOS=$(git ls-files $CHECKED_FILE_EXTENSIONS | \
    grep -v "todo-format" | \
    xargs -r grep -Hin -i "todo" 2>/dev/null | \
    grep -v -E "TODO(\(#[0-9]+\))?:" || true)

if [ -n "$INVALID_TODOS" ]; then
    echo "❌ Found TODO comments not matching the required format"
    echo ""
    echo "Valid formats:"
    echo "  TODO(#1234): description (with issue reference)"
    echo "  TODO: description (without issue reference)"
    echo ""
    echo "Invalid TODOs:"
    echo "$INVALID_TODOS"
    exit 1
fi

echo "✅ All TODO comments follow the required format"
exit 0
