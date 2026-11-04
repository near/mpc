#!/usr/bin/env bash
set -euo pipefail

CARGO_TOML="Cargo.toml"
TEST_UTILS_LIB="crates/test-utils/src/lib.rs"
NIX_SANDBOX="nix/near-sandbox.nix"

# Extract nearcore tag from a near-* dependency in workspace Cargo.toml
NEARCORE_VERSION=$(grep -m1 'git = "https://github.com/near/nearcore", tag' "$CARGO_TOML" | sed 's/.*tag = "\([^"]*\)".*/\1/')

# Extract version from DEFAULT_SANDBOX_VERSION constant (single source of truth in test-utils)
SANDBOX_VERSION=$(grep '^pub const DEFAULT_SANDBOX_VERSION' "$TEST_UTILS_LIB" | sed 's/.*"\([^"]*\)".*/\1/')

# Extract the version the nix dev shell pins near-sandbox to
NIX_SANDBOX_VERSION=$(grep -m1 '^  version = ' "$NIX_SANDBOX" | sed 's/.*"\([^"]*\)".*/\1/')

if [ -z "$NEARCORE_VERSION" ]; then
    echo "❌ Could not extract nearcore tag from $CARGO_TOML"
    exit 1
fi

if [ -z "$SANDBOX_VERSION" ]; then
    echo "❌ Could not extract DEFAULT_SANDBOX_VERSION from $TEST_UTILS_LIB"
    exit 1
fi

if [ -z "$NIX_SANDBOX_VERSION" ]; then
    echo "❌ Could not extract version from $NIX_SANDBOX"
    exit 1
fi

if [ "$NEARCORE_VERSION" != "$SANDBOX_VERSION" ] || [ "$NEARCORE_VERSION" != "$NIX_SANDBOX_VERSION" ]; then
    echo "❌ Sandbox image version mismatch"
    echo ""
    echo "  nearcore tag:            $NEARCORE_VERSION (from $CARGO_TOML)"
    echo "  DEFAULT_SANDBOX_VERSION: $SANDBOX_VERSION (from $TEST_UTILS_LIB)"
    echo "  nix near-sandbox:        $NIX_SANDBOX_VERSION (from $NIX_SANDBOX)"
    echo ""
    echo "Update DEFAULT_SANDBOX_VERSION in $TEST_UTILS_LIB and the version"
    echo "(plus tarball hashes) in $NIX_SANDBOX to match."
    exit 1
fi

echo "✅ Sandbox version matches nearcore ($NEARCORE_VERSION)"
exit 0
