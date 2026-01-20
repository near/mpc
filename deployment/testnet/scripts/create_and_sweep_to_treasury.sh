
#!/usr/bin/env bash
set -euo pipefail

TREASURY="${1:-barak_tee_test1.testnet}"
NETWORK="${2:-testnet}"               # could also be testnet-fastnear, testnet-lava
KEEP_NEAR="${3:-0.02}"                # keep a little for storage/fees
PREFIX="${4:-fundmyself}"             # account prefix
RPC_URL="https://rpc.testnet.near.org"

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
near send "${NEW_ACCOUNT}" "${TREASURY}" "${send_near}" --networkId "${NETWORK}"

echo
echo "Done."
echo "New account: ${NEW_ACCOUNT}"
echo "Key saved under legacy keychain in: ~/.near-credentials/testnet/"