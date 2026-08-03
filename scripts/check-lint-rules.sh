#!/usr/bin/env bash
# Check that the ast-grep rules under lints/ still fire.
#
# Scanning crates/ only proves the workspace is clean: a rule that has degraded into
# matching nothing passes that scan just as well as a working one. Each fixture marks
# its expected reports with a `VIOLATION` comment, and a rule has to report exactly
# those.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -a RULES=(
    "lints/mod-declaration-visibility-order.yml:lints/fixtures/visibility-order.rs"
    "lints/mod-declarations-contiguous.yml:lints/fixtures/declarations-contiguous.rs"
)

STATUS=0
for entry in "${RULES[@]}"; do
    rule="${entry%%:*}"
    fixture="${entry##*:}"

    expected=$(grep -c '//~ VIOLATION' "$fixture")
    # ast-grep exits non-zero whenever it reports something, which is the expected case here.
    actual=$({ ast-grep scan --rule "$rule" "$fixture" --json=compact || true; } |
        python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')

    if [ "$actual" -eq "$expected" ]; then
        echo "✅ $(basename "$rule"): reported $actual/$expected expected violations"
    else
        echo "❌ $(basename "$rule"): reported $actual violations, fixture marks $expected"
        ast-grep scan --rule "$rule" "$fixture" || true
        STATUS=1
    fi
done

exit $STATUS
