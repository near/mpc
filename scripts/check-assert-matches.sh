#!/usr/bin/env bash
set -euo pipefail

# Check that our crates use assert_matches!() instead of assert!(matches!()).
# The assert_matches! macro provides better error messages on failure.
#
# Exceptions: Lines preceded by a comment containing "assert_matches! requires"
# are allowed (e.g., when the matched type doesn't implement Debug).

VIOLATIONS=$(git ls-files -z "crates/*.rs" | \
    xargs -0 grep -Hn 'assert!(matches!(' || true)

# Filter out the script itself and empty lines
SCRIPT_NAME=$(basename "$0")
VIOLATIONS=$(echo "$VIOLATIONS" | grep -v "$SCRIPT_NAME" | grep -v '^$' || true)

if [ -n "$VIOLATIONS" ]; then
    # For each violation, check if the preceding line contains an exception comment
    REAL_VIOLATIONS=""
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        prev_lineno=$((lineno - 1))
        if [ "$prev_lineno" -gt 0 ]; then
            prev_line=$(sed -n "${prev_lineno}p" "$file")
            if echo "$prev_line" | grep -q "assert_matches! requires"; then
                continue
            fi
        fi
        REAL_VIOLATIONS="${REAL_VIOLATIONS}${line}\n"
    done <<< "$VIOLATIONS"

    # Remove trailing newline
    REAL_VIOLATIONS=$(echo -e "$REAL_VIOLATIONS" | grep -v '^$' || true)

    if [ -n "$REAL_VIOLATIONS" ]; then
        echo "❌ Found assert!(matches!(...)) — use assert_matches!() instead"
        echo ""
        echo "The assert_matches! macro (from the assert_matches crate) provides"
        echo "better error messages by showing the actual value on failure."
        echo ""
        echo "Replace:"
        echo "  assert!(matches!(expr, pattern));"
        echo "With:"
        echo "  assert_matches!(expr, pattern);"
        echo ""
        echo "If the matched type doesn't implement Debug, add this comment on the line above:"
        echo "  // assert_matches! requires Debug, which <Type> doesn't implement"
        echo ""
        echo "Violations found:"
        echo "$REAL_VIOLATIONS"
        exit 1
    fi
fi

echo "✅ No assert!(matches!(...)) found — all assertions use assert_matches!"
exit 0
