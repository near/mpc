#!/usr/bin/env bash
# Verify foreign chain transactions end to end on a running localnet whose nodes use the embedded
# foreign chain config. Votes the preset's RPC whitelist, waits for the chains to become available,
# then sends one `verify_foreign_transaction` per chain against a recent finalized transaction.
#
# Start the localnet first, with the API keys of the providers to test exported (see the header of
# launch-localnet.sh). Chains without an enabled provider never become available and are skipped.
#   ./scripts/launch-localnet.sh --rpc-preset mainnet
#
# Requirements: cargo curl jq near python3
#
# Usage:
#   ./scripts/localnet-verify-foreign-chains.sh [--rpc-preset <mainnet|testnet>] [--chains <A,B,...>] [--nodes <number_of_nodes>] [--whitelist <proposal.toml>] [--skip-vote]

set -euo pipefail

RPC_PRESET="mainnet"
CHAINS="Solana,Bnb,Base,Arbitrum,Polygon,Avalanche,HyperEvm,Fogo"
N=2
WHITELIST=""
SKIP_VOTE=false

MPC_CONTRACT="mpc-contract.test.near"
SIGNER="mpc-node-1.test.near"
AVAILABILITY_TIMEOUT_SEC=120

# Rent sysvar: its data never changes, so every node reads the same bytes.
SVM_ACCOUNT_STATE_PUBKEY="06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000"
# Vote program: on every SVM network it sees a steady stream of successful transactions, so
# getSignaturesForAddress always yields a recent one.
SVM_ANCHOR_ADDRESS="Vote111111111111111111111111111111111111111"

USAGE="Usage: $0 [--rpc-preset <mainnet|testnet>] [--chains <A,B,...>] [--nodes <number_of_nodes>] [--whitelist <proposal.toml>] [--skip-vote]"

while [[ $# -gt 0 ]]; do
  case "$1" in
  --rpc-preset)
    RPC_PRESET="$2"
    shift 2
    ;;
  --chains)
    CHAINS="$2"
    shift 2
    ;;
  --nodes)
    N="$2"
    shift 2
    ;;
  --whitelist)
    WHITELIST="$2"
    shift 2
    ;;
  --skip-vote)
    SKIP_VOTE=true
    shift
    ;;
  *)
    echo "Unknown parameter: $1"
    echo "$USAGE"
    exit 1
    ;;
  esac
done

main() {
  require_cmds cargo curl jq near python3

  case "$RPC_PRESET" in
  mainnet | testnet) ;;
  *) die "--rpc-preset must be mainnet or testnet" ;;
  esac
  : "${WHITELIST:=crates/proposal-generator/proposals/${RPC_PRESET}-rpc-whitelist.toml}"

  workdir=$(mktemp -d /tmp/mpc-localnet-foreign-chains.XXXXXX)
  echo "Logs will be stored in ${workdir}"

  IFS=',' read -ra chains <<<"$CHAINS"
  for chain in "${chains[@]}"; do
    public_rpc "$chain" >/dev/null || die "Unsupported chain: $chain"
  done

  if [[ "$SKIP_VOTE" == false ]]; then
    vote_whitelist
  fi

  echo "Waiting up to ${AVAILABILITY_TIMEOUT_SEC}s for chains to become available"
  local available
  available=$(wait_for_available "${chains[@]}")
  echo "Available: ${available}"

  local whitelisted
  whitelisted=$(eval "$(mpc_view allowed_foreign_chain_providers)" 2>/dev/null | jq -c 'keys')

  local requested=()
  for chain in "${chains[@]}"; do
    if ! jq -e --arg c "$chain" 'index($c)' <<<"$available" >/dev/null; then
      if jq -e --arg c "$chain" 'index($c)' <<<"$whitelisted" >/dev/null; then
        echo "SKIP ${chain}: not available (too few nodes cover it; check provider credentials)" >"${workdir}/${chain}.result"
      else
        echo "SKIP ${chain}: not whitelisted on the contract" >"${workdir}/${chain}.result"
      fi
      continue
    fi
    requested+=("$chain")
  done

  # Sequential: every request is signed with the same access key, so parallel sends race on its nonce.
  for chain in ${requested[@]+"${requested[@]}"}; do
    echo "Verifying ${chain}"
    verify_chain "$chain"
  done

  echo
  local failed=0
  for chain in "${chains[@]}"; do
    cat "${workdir}/${chain}.result"
    grep -q '^FAIL' "${workdir}/${chain}.result" && failed=1
  done
  return "$failed"
}

vote_whitelist() {
  local payload="${workdir}/whitelist.json"
  echo "Generating whitelist payload from ${WHITELIST}"
  cargo run -q --bin proposal-generator -- "$WHITELIST" >"$payload"
  local missing
  missing=$(jq -r --args '$ARGS.positional - (.votes | keys) | join(",")' "${chains[@]}" <"$payload")
  [[ -z "$missing" ]] || die "${WHITELIST} does not whitelist: ${missing}"

  echo "Voting whitelist from ${N} nodes"
  local pids=()
  for ((i = 1; i <= N; i++)); do
    run_quiet_on_success "$(mpc_tx vote_update_foreign_chain_providers "file-args ${payload}" '0 NEAR' "mpc-node-${i}.test.near")" &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do
    wait "$pid"
  done
}

# Prints the available chains as a JSON array once all `chains` are in it, or at the timeout.
wait_for_available() {
  local deadline=$((SECONDS + AVAILABILITY_TIMEOUT_SEC))
  local available="[]"
  while ((SECONDS < deadline)); do
    available=$(eval "$(mpc_view get_available_foreign_chains)" 2>/dev/null | jq -c '.' || echo "[]")
    if jq -e --args '$ARGS.positional - . | length == 0' "$@" <<<"$available" >/dev/null; then
      break
    fi
    sleep 5
  done
  echo "$available"
}

verify_chain() {
  local chain="$1"
  local args="${workdir}/${chain}.args.json"
  local log="${workdir}/${chain}.log"
  local result="${workdir}/${chain}.result"

  if ! request_args "$chain" >"$args" 2>"$log"; then
    echo "FAIL ${chain}: could not pick a transaction from $(public_rpc "$chain") (see ${log})" >"$result"
    return
  fi
  if eval "$(mpc_tx verify_foreign_transaction "file-args ${args}" '100 yoctoNEAR' "$SIGNER")" >>"$log" 2>&1; then
    echo "PASS ${chain}: tx $(jq -r '.request.request[].tx_id' "$args")" >"$result"
  else
    echo "FAIL ${chain}: see ${log}" >"$result"
  fi
}

request_args() {
  local chain="$1"
  local tx
  case "$chain" in
  Solana | Fogo)
    tx=$(svm_tx_id "$(public_rpc "$chain")") || return 1
    jq -n --arg chain "$chain" --arg tx "$tx" --arg pubkey "$SVM_ACCOUNT_STATE_PUBKEY" '
      {request: {request: {($chain): {
        tx_id: $tx,
        finality: "Finalized",
        extractors: [{AccountState: {pubkey: $pubkey}}]
      }}, domain_id: 3, payload_version: 1}}'
    ;;
  *)
    tx=$(evm_tx_id "$(public_rpc "$chain")") || return 1
    jq -n --arg chain "$chain" --arg tx "$tx" '
      {request: {request: {($chain): {
        tx_id: $tx,
        extractors: ["BlockHash"],
        finality: "Finalized"
      }}, domain_id: 3, payload_version: 1}}'
    ;;
  esac
}

# Public RPC used only to pick a transaction; the nodes query their own providers.
public_rpc() {
  case "${RPC_PRESET}/$1" in
  mainnet/Abstract) echo "https://api.mainnet.abs.xyz" ;;
  mainnet/Arbitrum) echo "https://arb1.arbitrum.io/rpc" ;;
  mainnet/Avalanche) echo "https://api.avax.network/ext/bc/C/rpc" ;;
  mainnet/Base) echo "https://mainnet.base.org" ;;
  mainnet/Bnb) echo "https://bsc-dataseed.bnbchain.org" ;;
  mainnet/Fogo) echo "https://mainnet.fogo.io" ;;
  mainnet/HyperEvm) echo "https://rpc.hyperliquid.xyz/evm" ;;
  mainnet/Polygon) echo "https://polygon-bor-rpc.publicnode.com" ;;
  mainnet/Solana) echo "https://api.mainnet-beta.solana.com" ;;
  testnet/Abstract) echo "https://api.testnet.abs.xyz" ;;
  testnet/Arbitrum) echo "https://sepolia-rollup.arbitrum.io/rpc" ;;
  testnet/Avalanche) echo "https://api.avax-test.network/ext/bc/C/rpc" ;;
  testnet/Base) echo "https://sepolia.base.org" ;;
  testnet/Bnb) echo "https://bsc-testnet-dataseed.bnbchain.org" ;;
  testnet/Fogo) echo "https://testnet.fogo.io" ;;
  testnet/HyperEvm) echo "https://rpc.hyperliquid-testnet.xyz/evm" ;;
  testnet/Polygon) echo "https://polygon-amoy-bor-rpc.publicnode.com" ;;
  testnet/Solana) echo "https://api.devnet.solana.com" ;;
  *) return 1 ;;
  esac
}

rpc_call() {
  local url="$1" method="$2" params="$3"
  curl -sf -m 20 -X POST -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" "$url"
}

# First transaction of the latest finalized block that has any, as hex without `0x`.
evm_tx_id() {
  local url="$1"
  local number tx
  number=$(rpc_call "$url" eth_getBlockByNumber '["finalized",false]' | jq -er '.result.number') || return 1
  for ((back = 0; back < 50; back++)); do
    tx=$(rpc_call "$url" eth_getBlockByNumber "[\"$(printf '0x%x' $((number - back)))\",false]" |
      jq -r '.result.transactions[0] // empty')
    if [[ -n "$tx" ]]; then
      echo "${tx#0x}"
      return
    fi
  done
  echo "no transaction in the last 50 finalized blocks" >&2
  return 1
}

# A recent successful finalized transaction signature, as 64-byte hex.
svm_tx_id() {
  local url="$1"
  local signature
  signature=$(rpc_call "$url" getSignaturesForAddress "[\"${SVM_ANCHOR_ADDRESS}\",{\"limit\":50,\"commitment\":\"finalized\"}]" |
    jq -er 'first(.result[] | select(.err == null) | .signature)') || return 1
  python3 -I -c '
import sys
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for c in sys.argv[1]:
    n = n * 58 + alphabet.index(c)
print(n.to_bytes(64, "big").hex())' "$signature"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmds() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || {
      printf 'Missing dependency: %s\n' "$cmd" >&2
      missing=1
    }
  done
  [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above."
}

mpc_tx() {
  local method="$1" args="$2" deposit="$3" signer="$4"
  echo "near contract call-function as-transaction ${MPC_CONTRACT} ${method} ${args} prepaid-gas '300.0 Tgas' attached-deposit '${deposit}' sign-as ${signer} network-config mpc-localnet sign-with-keychain send"
}

mpc_view() {
  local method="$1"
  echo "near contract call-function as-read-only ${MPC_CONTRACT} ${method} json-args {} network-config mpc-localnet now"
}

run_quiet_on_success() {
  local cmd="$1"
  local out
  out=$(mktemp "${workdir}/cmd.XXXXXX")
  if ! eval "$cmd" >"$out" 2>&1; then
    echo "FAILED: $cmd" >&2
    cat "$out" >&2
    return 1
  fi
}

main
