#!/usr/bin/env bash
# Check that all TODO comments in Rust files follow one of these formats:
# - // TODO(#NNN): description (with issue reference)
# - // TODO: description (without issue reference)
# This enforces uppercase TODO and proper formatting.

set -euo pipefail

# Find all .rs files, excluding the nearcore submodule and target directory
# Match lines containing TODO (case-insensitive) that do NOT match valid patterns
INVALID_TODOS=$(find . -name "*.rs" -type f \
    ! -path "./libs/nearcore/*" \
    ! -path "./target/*" \
    -exec grep -Hn -E "(//|///)[[:space:]]*(TODO|todo)" {} \; 2>/dev/null | \
    grep -v -E "(//|///)[[:space:]]*TODO(\(#[0-9]+\))?:" || true)

if [ -n "$INVALID_TODOS" ]; then
    echo "❌ Found TODO comments not matching the required format"
    echo ""
    echo "Valid formats:"
    echo "  // TODO(#1234): description (with issue reference)"
    echo "  // TODO: description (without issue reference)"
    echo ""
    echo "Invalid TODOs:"
    echo "$INVALID_TODOS"
    exit 1
fi

echo "✅ All TODO comments follow the required format"
exit 0
