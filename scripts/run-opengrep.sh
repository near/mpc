#!/usr/bin/env bash
# Canonical opengrep invocation, shared by `cargo make opengrep` and the CI job.
set -euo pipefail
cd "$(dirname "$0")/.."

# Only WARNING and ERROR findings block.
# panic-in-function-returning-result is excluded: docs/engineering-standards.md
# allows panics only in narrow cases, but we have a lot of such narrow cases.
exec opengrep scan \
    --config p/trailofbits \
    --config p/rust \
    --config p/secrets \
    --exclude-rule trailofbits.rs.panic-in-function-returning-result.panic-in-function-returning-result \
    --severity WARNING \
    --severity ERROR \
    --error
