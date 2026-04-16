#!/usr/bin/env bash
set -euo pipefail

# Checks the contract WASM binary size against a hard limit.
#
# NEAR's max_transaction_size (since protocol v69) is 1572864 bytes (1.5 MiB).
# We enforce a slightly tighter limit so the contract doesn't silently creep
# right up to the protocol boundary.
#
# Usage: bash scripts/check-contract-wasm-size.sh [path-to-wasm]

WASM_PATH="${1:-target/near/mpc_contract/mpc_contract.wasm}"

# NEAR max_transaction_size = 1572864; keep some headroom
HARD_LIMIT=1490000

if [[ ! -f "$WASM_PATH" ]]; then
    echo "❌ WASM file not found: $WASM_PATH"
    exit 1
fi

SIZE=$(wc -c < "$WASM_PATH" | tr -d ' ')
HEADROOM=$(( HARD_LIMIT - SIZE ))

echo "Contract WASM size report"
echo "========================="
echo "  Binary:     $WASM_PATH"
echo "  Size:       $SIZE bytes"
echo "  Hard limit: $HARD_LIMIT bytes"
echo "  Headroom:   $HEADROOM bytes"
echo ""

if [[ "$SIZE" -gt "$HARD_LIMIT" ]]; then
    OVER=$(( SIZE - HARD_LIMIT ))
    echo "❌ EXCEEDS hard limit by $OVER bytes"
    echo "   The contract binary is too large to deploy in a single transaction"
    echo "   Reduce size by removing methods, shrinking dependencies,"
    echo "   or optimizing the build profile"
    exit 1
fi

echo "✅ Contract size is within limits"
