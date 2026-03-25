#!/usr/bin/env bash
set -euo pipefail

# Check that our crates use assert_matches!() instead of assert!(matches!()).
# The assert_matches! macro provides better error messages on failure.
#
# Exceptions: Lines preceded by a comment containing "assert_matches! requires"
# are allowed (e.g., when the matched type doesn't implement Debug).

VIOLATIONS=$(git ls-files -z "crates/*.rs" | \
    xargs -0 grep -Hn 'assert!(matches!(' || true)

if [ -z "$VIOLATIONS" ]; then
    echo "✅ No non-exempt assert!(matches!(...)) found — all assertions use assert_matches!"
    exit 0
fi

# Filter out lines preceded by an exception comment
REAL_VIOLATIONS=()
while IFS= read -r line; do
    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    prev=$((lineno - 1))
    if [ "$prev" -gt 0 ] && sed -n "${prev}p" "$file" | grep -q "assert_matches! requires"; then
        continue
    fi
    REAL_VIOLATIONS+=("$line")
done <<< "$VIOLATIONS"

if [ "${#REAL_VIOLATIONS[@]}" -eq 0 ]; then
    echo "✅ No non-exempt assert!(matches!(...)) found — all assertions use assert_matches!"
    exit 0
fi

cat <<'MSG'
❌ Found assert!(matches!(...)) — use assert_matches!() instead

The assert_matches! macro (from the assert_matches crate) provides
better error messages by showing the actual value on failure.

Replace:
  assert!(matches!(expr, pattern));
With:
  assert_matches!(expr, pattern);

If the matched type doesn't implement Debug, add this comment on the line above:
  // assert_matches! requires Debug, which <Type> doesn't implement

Violations found:
MSG
printf '%s\n' "${REAL_VIOLATIONS[@]}"
exit 1
