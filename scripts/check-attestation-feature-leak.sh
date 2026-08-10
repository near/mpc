#!/usr/bin/env bash
set -euo pipefail

# Fails the build if `attestation/allow-pre-launch-script` is compiled into anything we ship.
#
# That feature makes attestation verification accept a CVM whose app-compose declares a
# `pre_launch_script`, which dstack runs as root before the node starts. Production rejects such an
# app-compose; tests need to accept one because the committed fixture is a real quote whose measured
# app-compose carries such a script, the one that exported the fixture node's signer key. A measured
# field cannot be dropped without invalidating the quote.
#
# Shipping it would let an operator run arbitrary root code in a CVM and still pass attestation.

FEATURE='allow-pre-launch-script'

# Each entry: <description>|<cargo tree args>. `no-dev` excludes dev-dependencies,
# matching what the release builds compile.
CONFIGURATIONS=(
  "mpc-contract wasm (cargo near build --features abi)|-p mpc-contract --features abi --target wasm32-unknown-unknown"
  "mpc-node binary|-p mpc-node"
  # Verifies attestations locally, so a relaxed policy here would report a
  # hook-carrying attestation as valid to an operator.
  "attestation-cli binary|-p attestation-cli"
  "tee-verifier wasm (cargo near build --features abi)|-p tee-verifier --features abi --target wasm32-unknown-unknown"
)

status=0
for configuration in "${CONFIGURATIONS[@]}"; do
    description="${configuration%%|*}"
    args="${configuration#*|}"

    echo "Checking $description ..."
    # shellcheck disable=SC2086 # word splitting is how the args are passed
    tree=$(cargo tree --edges features,no-dev --quiet $args 2>/dev/null)

    if [ -z "$tree" ]; then
        echo "❌ could not resolve the feature graph for $description"
        status=1
    elif grep -q "$FEATURE" <<<"$tree"; then
        echo "❌ $FEATURE is enabled in $description:"
        grep -B2 "$FEATURE" <<<"$tree"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    echo ""
    echo "$FEATURE must stay out of released artifacts. Enable it only on the"
    echo "dependency edges that build tests; see crates/attestation/Cargo.toml."
    exit 1
fi

echo "✅ $FEATURE is absent from every production feature graph"
