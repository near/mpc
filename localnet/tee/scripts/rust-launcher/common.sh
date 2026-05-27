#!/usr/bin/env bash
# =============================================================================
# Shared helpers for localnet/tee/scripts/rust-launcher/ scripts.
# =============================================================================
#
# Source this from a script as:
#
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/common.sh"
#
# This file is NOT meant to be executed directly. It defines:
#
#   - Coloured logging: log / warn / err / pass / fatal
#   - HOST_PROFILE → IP_PREFIX / IP_START_OCTET (alice + bob)
#   - ip_for_i              — per-index CVM IP
#   - ports_to_toml         — convert "host:container,…" to launcher TOML rows
#   - $CLI                  — wrapper for the dstack vmm-cli (requires BASE_PATH)
#   - near_call_ro / _tx    — concise wrappers around `near contract call-function`
#   - extract_json_ro / _tx — strip ANSI banners from near CLI output
#
# Callers are expected to have already set BASE_PATH, VMM_RPC,
# MPC_CONTRACT_ACCOUNT, and NEAR_NETWORK_CONFIG before invoking the
# near_call_* or $CLI plumbing. The HOST_PROFILE block runs at source-time
# and exits the caller with an error on an unknown profile.
# =============================================================================

# Refuse to be executed (only sourced).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "common.sh is meant to be sourced, not executed." >&2
  exit 1
fi

# ---- Logging --------------------------------------------------------------
# Errors go to stderr so they don't mix with stdout JSON captures.
log()   { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }
pass()  { echo -e "\033[1;32m[PASS]\033[0m $*"; }
fatal() { err "$*"; exit 1; }

# ---- Host profile → IP layout --------------------------------------------
# Sets IP_PREFIX and IP_START_OCTET. Bob's numbers match
# deploy-tee-cluster.sh's canonical values (5.196.36.<113+i>); the older
# test scripts used to disagree on bob, which is why this lives here now.
HOST_PROFILE="${HOST_PROFILE:-alice}"
case "$HOST_PROFILE" in
  alice) IP_PREFIX="51.68.219."; IP_START_OCTET=1   ;;
  bob)   IP_PREFIX="5.196.36." ; IP_START_OCTET=113 ;;
  *)
    echo "[ERROR] Unknown HOST_PROFILE=$HOST_PROFILE (supported: alice | bob)" >&2
    exit 1
    ;;
esac

# ---- Per-index IP helper -------------------------------------------------
ip_for_i() { echo "${IP_PREFIX}$((IP_START_OCTET + $1))"; }

# ---- ports_to_toml -------------------------------------------------------
# Convert a "host:container[,host:container]*" string into launcher TOML
# `port_mappings` rows. "host" in this TOML means the CVM-side port (the
# launcher's POV inside the CVM), NOT the QEMU host port — that mapping is
# done separately by deploy-launcher.sh's `--port` args.
ports_to_toml() {
  local ports="$1" result=""
  IFS=',' read -ra pairs <<< "$ports"
  for pair in "${pairs[@]}"; do
    local host_port="${pair%%:*}"
    local container_port="${pair##*:}"
    result+="    { host =$host_port, container =$container_port },
"
  done
  echo -n "$result"
}

# ---- dstack vmm-cli wrapper ----------------------------------------------
# $CLI is resolved at source-time, so callers that intend to use it MUST set
# BASE_PATH (and optionally VMM_RPC) BEFORE sourcing common.sh. Callers that
# don't need vmm-cli (e.g. single-node.sh, which uses inline python3
# invocations) can source common.sh before BASE_PATH is set — $CLI just
# stays unset, and any later use will trip `set -u` with a clear message.
if [ -n "${BASE_PATH:-}" ]; then
  CLI="python3 $BASE_PATH/vmm/src/vmm-cli.py --url ${VMM_RPC:-http://127.0.0.1:10000}"
fi

# ---- NEAR CLI wrappers ---------------------------------------------------
# Require MPC_CONTRACT_ACCOUNT and NEAR_NETWORK_CONFIG in the calling env.
# Output goes to stdout+stderr merged so callers can grep it; pair with
# extract_json_* below when only the JSON return value is wanted.
near_call_ro() {
  local method="$1" args="$2"
  near contract call-function as-read-only "$MPC_CONTRACT_ACCOUNT" "$method" \
    json-args "$args" network-config "$NEAR_NETWORK_CONFIG" now 2>&1
}
near_call_tx() {
  local method="$1" args="$2" signer="$3"
  near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" "$method" \
    json-args "$args" prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$signer" network-config "$NEAR_NETWORK_CONFIG" sign-with-keychain send 2>&1
}

# ---- JSON extraction from `near contract call-function` output -----------
# `near` writes JSON return values to stdout and ANSI banners to stderr; the
# `2>&1` in the wrappers above means both end up in the same stream, so we
# need to strip the banner lines to get parseable JSON.
extract_json_tx() {
  sed -n '/^Function execution return value/,/^$/{ /^Function/d; /^$/d; p }' \
    | sed '/^Here is your console/,$d' \
    | sed 's/^│[[:space:]]*//' \
    | sed '/^$/d'
}
extract_json_ro() {
  sed -n '/^Function execution return value/,/^Here is your console/{
    /^Function/d
    /^Here is your console/d
    p
  }'
}
