#!/usr/bin/env bash
set -euo pipefail

NEARCORE_TOML="libs/nearcore/Cargo.toml"
CLUSTER_RS="crates/e2e-tests/src/cluster.rs"

# Extract version from nearcore workspace Cargo.toml
NEARCORE_VERSION=$(grep -m1 '^version' "$NEARCORE_TOML" | sed 's/.*"\(.*\)".*/\1/')

# Extract version from DEFAULT_SANDBOX_IMAGE constant
SANDBOX_VERSION=$(grep '^const DEFAULT_SANDBOX_IMAGE' "$CLUSTER_RS" | sed 's/.*nearprotocol\/sandbox:\([^"]*\).*/\1/')

if [ "$NEARCORE_VERSION" != "$SANDBOX_VERSION" ]; then
    echo "❌ Sandbox image version mismatch"
    echo ""
    echo "  nearcore version:        $NEARCORE_VERSION (from $NEARCORE_TOML)"
    echo "  DEFAULT_SANDBOX_IMAGE:   $SANDBOX_VERSION (from $CLUSTER_RS)"
    echo ""
    echo "Update DEFAULT_SANDBOX_IMAGE in $CLUSTER_RS to match."
    exit 1
fi

echo "✅ Sandbox image version matches nearcore ($NEARCORE_VERSION)"
exit 0
