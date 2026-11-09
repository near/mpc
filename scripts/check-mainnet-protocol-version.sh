#!/usr/bin/env bash
set -euo pipefail

TEST_UTILS_LIB="crates/test-utils/src/lib.rs"
RPC_URL="${MAINNET_RPC_URL:-https://rpc.mainnet.near.org}"

PINNED=$(grep '^pub const MAINNET_PROTOCOL_VERSION' "$TEST_UTILS_LIB" | sed 's/.*= \([0-9]*\);/\1/')
if ! [[ $PINNED =~ ^[0-9]+$ ]]; then
    echo "Could not parse MAINNET_PROTOCOL_VERSION from $TEST_UTILS_LIB"
    exit 1
fi
LIVE=$(curl -sSf --retry 3 -X POST "$RPC_URL" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":"check","method":"status","params":[]}' | jq -er '.result.protocol_version')

if [ "$PINNED" != "$LIVE" ]; then
    echo "MAINNET_PROTOCOL_VERSION is $PINNED, mainnet runs protocol $LIVE."
    echo "Update MAINNET_PROTOCOL_VERSION in $TEST_UTILS_LIB."
    exit 1
fi

echo "MAINNET_PROTOCOL_VERSION matches mainnet ($LIVE)"
