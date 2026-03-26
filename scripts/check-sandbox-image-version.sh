#!/usr/bin/env bash
set -euo pipefail

CARGO_TOML="Cargo.toml"
CLUSTER_RS="crates/e2e-tests/src/cluster.rs"

# Extract nearcore tag from a near-* dependency in workspace Cargo.toml
NEARCORE_VERSION=$(grep -m1 'git = "https://github.com/near/nearcore", tag' "$CARGO_TOML" | sed 's/.*tag = "\([^"]*\)".*/\1/')

# Extract version from DEFAULT_SANDBOX_IMAGE constant
SANDBOX_VERSION=$(grep '^const DEFAULT_SANDBOX_IMAGE' "$CLUSTER_RS" | sed 's/.*nearprotocol\/sandbox:\([^"]*\).*/\1/')

if [ -z "$NEARCORE_VERSION" ]; then
    echo "❌ Could not extract nearcore tag from $CARGO_TOML"
    exit 1
fi

if [ "$NEARCORE_VERSION" != "$SANDBOX_VERSION" ]; then
    echo "❌ Sandbox image version mismatch"
    echo ""
    echo "  nearcore tag:            $NEARCORE_VERSION (from $CARGO_TOML)"
    echo "  DEFAULT_SANDBOX_IMAGE:   $SANDBOX_VERSION (from $CLUSTER_RS)"
    echo ""
    echo "Update DEFAULT_SANDBOX_IMAGE in $CLUSTER_RS to match."
    exit 1
fi

echo "✅ Sandbox image version matches nearcore ($NEARCORE_VERSION)"
exit 0
