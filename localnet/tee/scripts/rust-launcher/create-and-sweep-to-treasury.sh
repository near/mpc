#!/usr/bin/env bash
#
# Top up a testnet treasury account by sponsoring a fresh account via the
# faucet, waiting for it on-chain, and sweeping its balance (minus a small
# storage/fee reserve) to the treasury.
#
# Useful before running `deploy-tee-cluster.sh MODE=testnet` if your
# `FUNDER_ACCOUNT` is short on NEAR — the testnet faucet caps at ~10 NEAR
# per account, so consolidate by running this 2–3 times.
#
# Usage:
#   bash create-and-sweep-to-treasury.sh <treasury_account.testnet>
#   bash create-and-sweep-to-treasury.sh <treasury> [network] [keep_near] [prefix]
#
# Each run creates ONE fresh `<prefix>-<6hex>.testnet` and sweeps it.
#
# Originally from PR #1803; ported into this directory in PR #2952
# (alongside `deploy-tee-cluster.sh` so operators don't have to chase
# scripts across the tree).

set -euo pipefail

TREASURY="${1:?Usage: $0 <treasury_account.testnet> [network] [keep_near] [prefix]}"
NETWORK="${2:-testnet}"               # could also be testnet-fastnear, testnet-lava
KEEP_NEAR="${3:-0.02}"                # keep a little for storage/fees
PREFIX="${4:-fundmyself}"             # account prefix
RPC_URL="${RPC_URL:-https://rpc.testnet.near.org}"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 1; }; }
need_cmd near
need_cmd curl
need_cmd jq
need_cmd python3

# Random suffix: 6 hex chars
SUFFIX="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(3))
PY
)"

NEW_ACCOUNT="${PREFIX}-${SUFFIX}.testnet"

echo "Treasury:     ${TREASURY}"
echo "NetworkId:    ${NETWORK}"
echo "New account:  ${NEW_ACCOUNT}"
echo "Keep:         ${KEEP_NEAR} NEAR"
echo

echo "Creating account via faucet sponsorship..."
near account create-account sponsor-by-faucet-service "${NEW_ACCOUNT}" \
  autogenerate-new-keypair save-to-legacy-keychain \
  network-config "${NETWORK}" create

echo
echo "Waiting for account to appear on-chain..."
for i in {1..30}; do
  payload='{"jsonrpc":"2.0","id":"1","method":"query","params":{"request_type":"view_account","finality":"final","account_id":"'"$NEW_ACCOUNT"'"}}'
  out="$(curl -sS "${RPC_URL}" -H 'Content-Type: application/json' -d "${payload}" || true)"
  if [[ -n "$out" ]] && ! echo "$out" | jq -e '.error' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if [[ -z "${out:-}" ]] || echo "$out" | jq -e '.error' >/dev/null 2>&1; then
  echo "Account did not become queryable in time. Try checking manually:"
  echo "  near state ${NEW_ACCOUNT} --networkId ${NETWORK}"
  exit 1
fi

amount_yocto="$(echo "$out" | jq -r '.result.amount')"
locked_yocto="$(echo "$out" | jq -r '.result.locked')"

avail_yocto="$(python3 - <<PY
a=int("$amount_yocto")
l=int("$locked_yocto")
print(max(a-l,0))
PY
)"

avail_near="$(python3 - <<PY
from decimal import Decimal, getcontext
getcontext().prec=60
print(Decimal("$avail_yocto")/Decimal(10)**24)
PY
)"

send_near="$(python3 - <<PY
from decimal import Decimal, getcontext
getcontext().prec=60
avail=Decimal("$avail_near")
keep=Decimal("$KEEP_NEAR")
x=avail-keep
if x <= 0:
    print("0")
else:
    print(x.quantize(Decimal("0.000001")))
PY
)"

echo "On-chain available ~ ${avail_near} NEAR"
if [[ "$send_near" == "0" || "$send_near" == "0.000000" ]]; then
  echo "Nothing to sweep after keeping ${KEEP_NEAR} NEAR."
  echo "Done."
  exit 0
fi

echo "Sweeping ~ ${send_near} NEAR -> ${TREASURY}"
near tokens "${NEW_ACCOUNT}" send-near "${TREASURY}" "${send_near} NEAR" \
  network-config "${NETWORK}" sign-with-keychain send

echo
echo "Done."
echo "New account: ${NEW_ACCOUNT}"
echo "Key saved under legacy keychain in: ~/.near-credentials/testnet/"
