#!/usr/bin/env bash
#
# Unsticks a `vote_update` that exceeds the per-receipt storage proof limit.
#
# The deciding vote sweeps every stored proposal in one receipt. The limit is a delta against a
# recorder shared by the whole chunk, and that recorder bills a trie value once per chunk, so a
# cheap receipt running earlier in the same chunk that reads one stored proposal takes its bytes
# off the vote's bill. This signs a gas-capped `proposed_updates` probe and the deciding vote under
# consecutive nonces of one access key, then broadcasts both without waiting, so they land in one
# chunk with the probe first.
#
# Ordering inside a chunk is guaranteed only between consecutive nonces of one key, so the probe
# must be sent by the same account that casts the vote. A failed attempt burns gas, changes no
# state and leaves the standing votes intact, so just run it again.
#
# Background, evidence and sizing: incident-vote-update-storage-proof.md
#
# Usage:  SIGNER=<voter account> ./recover-vote-update.sh          # signs only, sends nothing
#         SIGNER=<voter account> SEND=yes ./recover-vote-update.sh # signs and broadcasts

set -euo pipefail

SIGNER=${SIGNER:?set SIGNER to the account casting the deciding vote}
CONTRACT=${CONTRACT:-v1.signer}
NETWORK=${NETWORK:-mainnet}
RPC=${RPC:-https://rpc.mainnet.fastnear.com}
UPDATE_ID=${UPDATE_ID:-18}
# At a proposal size of 1,229,682 bytes the probe records one entry between roughly 11 and 51 TGas,
# and two between roughly 52 and 93. Below the window it records nothing and the vote fails again.
PROBE_GAS=${PROBE_GAS:-30}
VOTE_GAS=${VOTE_GAS:-300}
SEND=${SEND:-no}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Nonce and a recent block from one query, so both transactions share the block hash.
public_key="ed25519:2kriEWiWbGTPdShjBuiVStURJQNHAzHXERpDDtJ9Z8bD"
access_key=$(curl -sS "$RPC" -H 'content-type: application/json' -d '{
  "jsonrpc": "2.0", "id": "1", "method": "query",
  "params": {"request_type": "view_access_key", "finality": "final",
             "account_id": "'"$SIGNER"'", "public_key": "'"$public_key"'"}}')
nonce=$(jq -r .result.nonce <<<"$access_key")
block_hash=$(jq -r .result.block_hash <<<"$access_key")
block_height=$(jq -r .result.block_height <<<"$access_key")

# near-cli-rs honours --nonce only in offline mode, which is what lets the two transactions carry
# consecutive nonces without either of them having landed yet.
sign() { # method json-args tgas nonce output-file
  near --quiet --offline contract call-function as-transaction "$CONTRACT" "$1" json-args "$2" \
    prepaid-gas "$3 Tgas" attached-deposit '0 NEAR' \
    sign-as "$SIGNER" network-config "$NETWORK" \
    sign-with-keychain \
    --nonce "$4" --block-hash "$block_hash" --block-height "$block_height" \
    save-to-file "$5" >/dev/null 2>&1
}

sign proposed_updates '{}' "$PROBE_GAS" "$((nonce + 1))" "$work/probe.json"
sign vote_update "{\"id\": $UPDATE_ID}" "$VOTE_GAS" "$((nonce + 2))" "$work/vote.json"

broadcast() { # signed-transaction-file
  curl -sS "$RPC" -H 'content-type: application/json' -d '{
    "jsonrpc": "2.0", "id": "1", "method": "broadcast_tx_async",
    "params": ["'"$(jq -r .signed_transaction_as_base64 "$1")"'"]}'
}

echo "signer   $SIGNER, nonces $((nonce + 1)) and $((nonce + 2)), block $block_height"
echo "probe    proposed_updates {} at $PROBE_GAS TGas"
echo "vote     vote_update {\"id\": $UPDATE_ID} at $VOTE_GAS TGas on $CONTRACT"

if [ "$SEND" != yes ]; then
  echo
  echo "signed, nothing sent. Set SEND=yes to broadcast. Signed transactions:"
  jq -r .signed_transaction_as_base64 "$work/probe.json"
  jq -r .signed_transaction_as_base64 "$work/vote.json"
  exit 0
fi

# Both in the background so neither waits for the other. Arrival order does not matter: inside a
# chunk the pool orders one key's transactions by nonce, which puts the probe first.
broadcast "$work/probe.json" >"$work/probe.out" &
broadcast "$work/vote.json" >"$work/vote.out" &
wait

echo
echo "probe    $(cat "$work/probe.out")"
echo "vote     $(cat "$work/vote.out")"
echo
echo "sent. Check the two hashes with:"
echo "  near transaction view-status <hash> network-config $NETWORK"
echo "Expect the probe to fail with 'Exceeded the prepaid gas' and the vote to succeed."
echo "Then confirm the proposals are gone and the code changed:"
echo "  mpc-contract.sh view proposed_updates"
echo "  mpc-contract.sh state"
