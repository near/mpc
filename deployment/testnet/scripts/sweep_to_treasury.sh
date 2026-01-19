
#!/usr/bin/env bash
set -euo pipefail

CREDS_DIR="/home/ubuntu/.near-credentials/testnet"
TREASURY="${1:-}"
KEEP_NEAR="${2:-0.25}"     # keep this much NEAR in each source account
NETWORK="testnet"
RPC_URL="https://rpc.testnet.near.org"

if [[ -z "${TREASURY}" ]]; then
  echo "Usage: $0 <treasury_account.testnet> [keep_near]"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found. Install: sudo apt-get update && sudo apt-get install -y jq"
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found. Install: sudo apt-get update && sudo apt-get install -y curl"
  exit 1
fi
if ! command -v near >/dev/null 2>&1; then
  echo "near CLI not found in PATH."
  exit 1
fi

shopt -s nullglob
files=("${CREDS_DIR}"/*.testnet.json)
if (( ${#files[@]} == 0 )); then
  echo "No credential files found in ${CREDS_DIR}"
  exit 1
fi

echo "Treasury: ${TREASURY}"
echo "Keeping:  ${KEEP_NEAR} NEAR per source account"
echo

yocto_per_near="1000000000000000000000000"

# Function: query account via RPC, return amount_yocto locked_yocto or empty on error
rpc_view_account () {
  local acct="$1"
  local payload
  payload='{"jsonrpc":"2.0","id":"1","method":"query","params":{"request_type":"view_account","finality":"final","account_id":"'"$acct"'"}}'
  local out
  out="$(curl -sS "${RPC_URL}" -H 'Content-Type: application/json' -d "${payload}")" || return 1
  # If error, return non-zero
  if echo "$out" | jq -e '.error' >/dev/null 2>&1; then
    return 2
  fi
  local amount locked
  amount="$(echo "$out" | jq -r '.result.amount // empty')"
  locked="$(echo "$out" | jq -r '.result.locked // empty')"
  if [[ -z "$amount" || -z "$locked" ]]; then
    return 3
  fi
  echo "${amount} ${locked}"
}

# Convert yocto -> NEAR (decimal string)
yocto_to_near () {
  python3 - <<PY
from decimal import Decimal, getcontext
getcontext().prec=60
y=Decimal("$1")
print(y/Decimal(10)**24)
PY
}

# Compute sweep amount = max((avail - keep), 0) with 6 decimals
compute_sweep () {
  python3 - <<PY
from decimal import Decimal, getcontext
getcontext().prec=60
avail=Decimal("$1")
keep=Decimal("$2")
x=avail-keep
if x <= 0:
    print("0")
else:
    print(x.quantize(Decimal("0.000001")))
PY
}

for f in "${files[@]}"; do
  acct="$(basename "$f" .json)"

  # Skip treasury itself
  if [[ "$acct" == "$TREASURY" ]]; then
    continue
  fi

  echo "== $acct =="

  # Query balance via RPC
  if ! pair="$(rpc_view_account "$acct")"; then
    echo "  RPC query failed. Skipping."
    echo
    continue
  fi

  amount_yocto="$(echo "$pair" | awk '{print $1}')"
  locked_yocto="$(echo "$pair" | awk '{print $2}')"

  # available = amount - locked
  avail_yocto="$(python3 - <<PY
a=int("$amount_yocto")
l=int("$locked_yocto")
print(max(a-l,0))
PY
)"
  avail_near="$(yocto_to_near "$avail_yocto")"
  send_near="$(compute_sweep "$avail_near" "$KEEP_NEAR")"

  if [[ "$send_near" == "0" || "$send_near" == "0.000000" ]]; then
    echo "  Available ~ ${avail_near} NEAR; nothing to sweep after keeping ${KEEP_NEAR}"
    echo
    continue
  fi

  echo "  Available ~ ${avail_near} NEAR"
  echo "  Sweeping  ~ ${send_near} NEAR -> ${TREASURY}"

  # Do the transfer
  if ! near send "$acct" "$TREASURY" "$send_near" --networkId "$NETWORK"; then
    echo "  Transfer failed for $acct (likely storage/locked). Continuing."
    echo
    continue
  fi
  echo
done

echo "Done."


