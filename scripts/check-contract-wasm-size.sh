#!/usr/bin/env bash
set -euo pipefail

# Checks the contract WASM binary size against:
# 1. NEAR's max_transaction_size hard limit
# 2. A committed baseline that ratchets down over time
#
# Usage: bash scripts/check-contract-wasm-size.sh [path-to-wasm]

WASM_PATH="${1:-target/near/mpc_contract/mpc_contract.wasm}"
BASELINE_FILE=".github/contract-size-baseline.toml"

read_toml_value() {
    grep "^$1 " "$BASELINE_FILE" | sed 's/.*= *//'
}

if [[ ! -f "$WASM_PATH" ]]; then
    echo "❌ WASM file not found: $WASM_PATH"
    exit 1
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "❌ Baseline file not found: $BASELINE_FILE"
    exit 1
fi

MAX_TX_SIZE=$(read_toml_value "max_transaction_size")
BASELINE=$(read_toml_value "expected_size")

if [[ -z "$MAX_TX_SIZE" || -z "$BASELINE" ]]; then
    echo "❌ Failed to read max_transaction_size or expected_size from $BASELINE_FILE"
    exit 1
fi

SIZE=$(wc -c < "$WASM_PATH" | tr -d ' ')
HEADROOM=$(( MAX_TX_SIZE - SIZE ))
ACCEPTABLE_INCREASE=500
DELTA=$(( SIZE - BASELINE ))

echo "Contract WASM size report"
echo "========================="
echo "  Binary:     $WASM_PATH"
echo "  Size:       $SIZE bytes"
echo "  Hard limit: $MAX_TX_SIZE bytes (NEAR max_transaction_size)"
echo "  Headroom:   $HEADROOM bytes"
echo "  Baseline:   $BASELINE bytes"
if [[ "$DELTA" -gt 0 ]]; then
    echo "  Delta:      +$DELTA bytes"
elif [[ "$DELTA" -lt 0 ]]; then
    echo "  Delta:      $DELTA bytes"
fi
echo ""

# Hard limit check
if [[ "$SIZE" -gt "$MAX_TX_SIZE" ]]; then
    OVER=$(( SIZE - MAX_TX_SIZE ))
    echo "❌ EXCEEDS hard limit by $OVER bytes"
    echo "   The contract binary is too large to deploy in a single transaction"
    echo "   Reduce size by removing methods, shrinking dependencies,"
    echo "   or optimizing the build profile"
    exit 1
fi

# Baseline check
if [[ "$DELTA" -gt "$ACCEPTABLE_INCREASE" ]]; then
    echo "❌ Contract grew by $DELTA bytes, which is greater than $ACCEPTABLE_INCREASE"
    echo "   If this growth is intentional, update the baseline in $BASELINE_FILE:"
    echo "   expected_size = $SIZE"
    exit 1
elif [[ "$DELTA" -gt 0 ]]; then
    echo "⚠️ Contract grew by $DELTA bytes — consider updating the baseline in $BASELINE_FILE:"
    echo "   expected_size = $SIZE"
elif [[ "$DELTA" -lt 0 ]]; then
    SHRINK=$(( BASELINE - SIZE ))
    echo "🎉 Contract shrank by $SHRINK bytes — consider updating the baseline in $BASELINE_FILE:"
    echo "   expected_size = $SIZE"
else
    echo "✅ Contract size matches baseline"
fi
