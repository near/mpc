#!/usr/bin/env bash
# Verify every (chain, provider) combo in foreign_chains.yaml with a single
# JSON-RPC call. Chains with sample_tx_id use the same method the node's
# startup probe would (`eth_getTransactionReceipt` / `getrawtransaction`);
# chains without a sample fall back to a generic lightweight method
# (`eth_chainId` / `starknet_chainId` / `getHealth`) to prove auth+URL work.
#
# Rate-limit conscious: one request per combo, 1s delay between requests
# (pass `--no-sleep` to disable).

set -uo pipefail

SLEEP=1
[[ "${1:-}" == "--no-sleep" ]] && SLEEP=0

# Load API keys from .env (gitignored). Same VAR names that foreign_chains.yaml
# references via `{ env: <NAME> }`, so the YAML and script stay in sync.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE — populate it with provider API keys before running." >&2
  exit 2
fi
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${ANKR_API_KEY:?ANKR_API_KEY must be set in .env}"
: "${BLOCKDAEMON_API_KEY:?BLOCKDAEMON_API_KEY must be set in .env}"
: "${BLOCKPI_API_KEY:?BLOCKPI_API_KEY must be set in .env}"
: "${DRPC_API_KEY:?DRPC_API_KEY must be set in .env}"
: "${DWELLIR_API_KEY:?DWELLIR_API_KEY must be set in .env}"
: "${INFURA_API_KEY:?INFURA_API_KEY must be set in .env}"
: "${NOWNODES_API_KEY:?NOWNODES_API_KEY must be set in .env}"
: "${TATUM_API_KEY:?TATUM_API_KEY must be set in .env}"

ANKR_KEY="$ANKR_API_KEY"
BLOCKDAEMON_KEY="$BLOCKDAEMON_API_KEY"
BLOCKPI_KEY="$BLOCKPI_API_KEY"
DRPC_KEY="$DRPC_API_KEY"
DWELLIR_KEY="$DWELLIR_API_KEY"
INFURA_KEY="$INFURA_API_KEY"
NOWNODES_KEY="$NOWNODES_API_KEY"
TATUM_KEY="$TATUM_API_KEY"

BTC_TX="58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c"
ETH_TX="0x596b624cfd6ed5723cf60422a199d10f2b5be8c87c07db8e2643c259414d960a"
BNB_TX="0x90514fff1563dc9876bc9a02a7b1d4dd2ce44b8d11ea0490aa8d427166eba349"
POLYGON_TX="0x7b231f0f5bf36782a48db9b1d89e4613bd00618f03c3c0fba922aa59288e4d38"
ARB_TX="0x8f1f497285dcf54624cba2c3dd46d13e25fc83466033c139e77e4dce12a1e484"
BASE_TX="0xa11eaa1236e80f26ddc7aca164f2ba4c6c2726405cb12b1aa8f52c520bad99e1"
HYPEREVM_TX="0x4d94e2c9c33c533f125bd28a788e80ee24c108356e8fa8a7878f642cf94dcf4a"
STARKNET_TX="0x7a7645a2672354006c5209ce40d6060c3aa14d581ccdfd3825f5af73b3959c5"
SOLANA_TX="4KgPsECUGeSgtKmQ2P8YAF7LwsQ61YW3S5nAh8yWcBrBt2g9CjwLwjEH8cneHxugrvoiNSY7RTtEYp7zfWQUza6E"

PASS=0
FAIL=0
printf "%-10s  %-12s  %-6s  %-6s  %s\n" "CHAIN" "PROVIDER" "STATUS" "HTTP" "DETAIL"
printf "%-10s  %-12s  %-6s  %-6s  %s\n" "-----" "--------" "------" "----" "------"

probe() {
  local chain=$1
  local provider=$2
  local method=$3
  local params=$4
  shift 4

  local body
  body=$(printf '{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}' "$method" "$params")
  local tmp_resp; tmp_resp=$(mktemp)
  local tmp_err; tmp_err=$(mktemp)

  local http
  http=$(curl --silent --show-error --max-time 15 \
    -o "$tmp_resp" -w "%{http_code}" \
    -H "Content-Type: application/json" -X POST --data "$body" \
    "$@" 2>"$tmp_err")
  local rc=$?

  local resp; resp=$(cat "$tmp_resp")
  local status detail

  if [[ $rc -ne 0 ]]; then
    status="FAIL"; detail="curl_rc=$rc $(cat "$tmp_err" | head -c 200)"
  elif [[ ! "$http" =~ ^2 ]]; then
    status="FAIL"; detail="body=$(echo "$resp" | head -c 200 | tr -d '\n')"
  elif command -v jq >/dev/null 2>&1; then
    local has_error result_kind
    has_error=$(jq -r '.error // empty | tojson' <<<"$resp" 2>/dev/null)
    result_kind=$(jq -r '.result | type' <<<"$resp" 2>/dev/null)
    if [[ -n "$has_error" && "$has_error" != "null" && "$has_error" != "{}" ]]; then
      status="FAIL"; detail="rpc_error=$(echo "$has_error" | head -c 200)"
    elif [[ -z "$result_kind" || "$result_kind" == "null" ]]; then
      status="FAIL"; detail="result_null body=$(echo "$resp" | head -c 200 | tr -d '\n')"
    else
      status="PASS"; detail="result_type=$result_kind"
    fi
  else
    if [[ "$resp" == *'"error"'* ]]; then
      status="FAIL"; detail=$(echo "$resp" | head -c 200 | tr -d '\n')
    elif [[ "$resp" == *'"result"'* ]]; then
      status="PASS"; detail="result present (jq missing)"
    else
      status="FAIL"; detail=$(echo "$resp" | head -c 200 | tr -d '\n')
    fi
  fi

  if [[ "$status" == "PASS" ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  printf "%-10s  %-12s  %-6s  %-6s  %s\n" "$chain" "$provider" "$status" "$http" "$detail"
  rm -f "$tmp_resp" "$tmp_err"
  sleep "$SLEEP"
}

probe_evm_receipt() { local c=$1 p=$2 t=$3; shift 3; probe "$c" "$p" "eth_getTransactionReceipt" "[\"$t\"]" "$@"; }
probe_btc_tx()      { probe "$1" "$2" "getrawtransaction" "[\"$3\",true]" "${@:4}"; }
probe_solana_tx() {
  local c=$1 p=$2 sig=$3; shift 3
  probe "$c" "$p" "getTransaction" "[\"$sig\",{\"encoding\":\"json\",\"maxSupportedTransactionVersion\":0,\"commitment\":\"finalized\"}]" "$@"
}
probe_starknet_receipt() { local c=$1 p=$2 t=$3; shift 3; probe "$c" "$p" "starknet_getTransactionReceipt" "[\"$t\"]" "$@"; }

# ---------------------------------------------------------------------------
# bitcoin
# ---------------------------------------------------------------------------
probe_btc_tx bitcoin ankr        "$BTC_TX" "https://rpc.ankr.com/btc/$ANKR_KEY"
probe_btc_tx bitcoin blockdaemon "$BTC_TX" "https://svc.blockdaemon.com/bitcoin/mainnet/native" -H "Authorization: Bearer $BLOCKDAEMON_KEY"
probe_btc_tx bitcoin drpc        "$BTC_TX" "https://lb.drpc.org/ogrpc?network=bitcoin&dkey=$DRPC_KEY"
probe_btc_tx bitcoin nownodes    "$BTC_TX" "https://btc.nownodes.io/" -H "api-key: $NOWNODES_KEY"
probe_btc_tx bitcoin tatum       "$BTC_TX" "https://bitcoin-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# ethereum
# ---------------------------------------------------------------------------
probe_evm_receipt ethereum ankr        "$ETH_TX" "https://rpc.ankr.com/eth/$ANKR_KEY"
probe_evm_receipt ethereum blockdaemon "$ETH_TX" "https://svc.blockdaemon.com/ethereum/mainnet/native" -H "Authorization: Bearer $BLOCKDAEMON_KEY"
probe_evm_receipt ethereum blockpi     "$ETH_TX" "https://ethereum.blockpi.network/v1/rpc/$BLOCKPI_KEY"
probe_evm_receipt ethereum drpc        "$ETH_TX" "https://lb.drpc.org/ogrpc?network=ethereum&dkey=$DRPC_KEY"
probe_evm_receipt ethereum dwellir     "$ETH_TX" "https://api-ethereum-mainnet.n.dwellir.com/$DWELLIR_KEY"
probe_evm_receipt ethereum infura      "$ETH_TX" "https://mainnet.infura.io/v3/$INFURA_KEY"
probe_evm_receipt ethereum tatum       "$ETH_TX" "https://ethereum-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# bnb
# ---------------------------------------------------------------------------
probe_evm_receipt bnb ankr    "$BNB_TX" "https://rpc.ankr.com/bsc/$ANKR_KEY"
probe_evm_receipt bnb drpc    "$BNB_TX" "https://lb.drpc.org/ogrpc?network=bsc&dkey=$DRPC_KEY"
probe_evm_receipt bnb dwellir "$BNB_TX" "https://api-bsc-mainnet-full.n.dwellir.com/$DWELLIR_KEY"
probe_evm_receipt bnb infura  "$BNB_TX" "https://bsc-mainnet.infura.io/v3/$INFURA_KEY"
probe_evm_receipt bnb tatum   "$BNB_TX" "https://bsc-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# polygon
# ---------------------------------------------------------------------------
probe_evm_receipt polygon ankr        "$POLYGON_TX" "https://rpc.ankr.com/polygon/$ANKR_KEY"
probe_evm_receipt polygon blockdaemon "$POLYGON_TX" "https://svc.blockdaemon.com/polygon/mainnet/native/http-rpc" -H "Authorization: Bearer $BLOCKDAEMON_KEY"
probe_evm_receipt polygon drpc        "$POLYGON_TX" "https://lb.drpc.org/ogrpc?network=polygon&dkey=$DRPC_KEY"
probe_evm_receipt polygon dwellir     "$POLYGON_TX" "https://api-polygon-mainnet-full.n.dwellir.com/$DWELLIR_KEY"
probe_evm_receipt polygon infura      "$POLYGON_TX" "https://polygon-mainnet.infura.io/v3/$INFURA_KEY"
probe_evm_receipt polygon nownodes    "$POLYGON_TX" "https://matic.nownodes.io/" -H "api-key: $NOWNODES_KEY"
probe_evm_receipt polygon tatum       "$POLYGON_TX" "https://polygon-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# arbitrum
# ---------------------------------------------------------------------------
probe_evm_receipt arbitrum ankr        "$ARB_TX" "https://rpc.ankr.com/arbitrum/$ANKR_KEY"
probe_evm_receipt arbitrum blockdaemon "$ARB_TX" "https://svc.blockdaemon.com/arbitrum/mainnet-one/native/http-rpc" -H "Authorization: Bearer $BLOCKDAEMON_KEY"
probe_evm_receipt arbitrum drpc        "$ARB_TX" "https://lb.drpc.org/ogrpc?network=arbitrum&dkey=$DRPC_KEY"
probe_evm_receipt arbitrum dwellir     "$ARB_TX" "https://api-arbitrum-mainnet-archive.n.dwellir.com/$DWELLIR_KEY"
probe_evm_receipt arbitrum infura      "$ARB_TX" "https://arbitrum-mainnet.infura.io/v3/$INFURA_KEY"
probe_evm_receipt arbitrum nownodes    "$ARB_TX" "https://arbitrum.nownodes.io/" -H "api-key: $NOWNODES_KEY"
probe_evm_receipt arbitrum tatum       "$ARB_TX" "https://arb-one-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# base
# ---------------------------------------------------------------------------
probe_evm_receipt base ankr        "$BASE_TX" "https://rpc.ankr.com/base/$ANKR_KEY"
probe_evm_receipt base blockdaemon "$BASE_TX" "https://svc.blockdaemon.com/base/mainnet/native/http-rpc" -H "Authorization: Bearer $BLOCKDAEMON_KEY"
probe_evm_receipt base dwellir     "$BASE_TX" "https://api-base-mainnet-archive.n.dwellir.com/$DWELLIR_KEY"
probe_evm_receipt base tatum       "$BASE_TX" "https://base-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# hyper_evm
# ---------------------------------------------------------------------------
probe_evm_receipt hyper_evm drpc "$HYPEREVM_TX" "https://lb.drpc.org/ogrpc?network=hyperliquid&dkey=$DRPC_KEY"

# ---------------------------------------------------------------------------
# solana (probe code does not iterate solana yet; sample fetched via getTransaction)
# ---------------------------------------------------------------------------
probe_solana_tx solana blockdaemon "$SOLANA_TX" "https://svc.blockdaemon.com/solana/mainnet/native" -H "Authorization: Bearer $BLOCKDAEMON_KEY"
probe_solana_tx solana nownodes    "$SOLANA_TX" "https://sol.nownodes.io/" -H "api-key: $NOWNODES_KEY"
probe_solana_tx solana tatum       "$SOLANA_TX" "https://solana-mainnet.gateway.tatum.io/" -H "x-api-key: $TATUM_KEY"

# ---------------------------------------------------------------------------
# starknet
# ---------------------------------------------------------------------------
probe_starknet_receipt starknet dwellir "$STARKNET_TX" "https://api-starknet-mainnet.n.dwellir.com/$DWELLIR_KEY"
probe_starknet_receipt starknet infura  "$STARKNET_TX" "https://starknet-mainnet.infura.io/v3/$INFURA_KEY"

printf "\n"
printf "Summary: %d PASS, %d FAIL\n" "$PASS" "$FAIL"
exit $(( FAIL == 0 ? 0 : 1 ))
