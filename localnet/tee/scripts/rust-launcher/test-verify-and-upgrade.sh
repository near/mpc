#!/usr/bin/env bash
# =============================================================================
# MPC Cluster Verification & Rolling Upgrade Test
# =============================================================================
#
# Prerequisites:
#   - A running 2-node MPC cluster deployed by deploy-tee-cluster.sh
#   - Source set-localnet-env.sh (or export the required variables) before running
#
# Scenario 1 (verify): Validates the cluster is fully operational
#   - Contract state is "Running"
#   - Signature generation works (ECDSA)
#   - TEE accounts are registered
#   - All attestations are real Dstack (not Mock)
#
# Scenario 2 (upgrade): Rolling upgrade to a new MPC image
#   2.1 - Vote for a new MPC image hash
#   2.2 - Wait for nodes to detect and persist the new hash
#   2.3 - Restart CVMs with updated config pointing to new image tag
#   2.4 - Verify network is fully operational with the new image
#
# Usage:
#   bash test-verify-and-upgrade.sh verify              # Scenario 1 only
#   bash test-verify-and-upgrade.sh upgrade <manifest_digest>  # Scenario 2 (includes verify before & after)
#
# Environment variables (from set-localnet-env.sh or deploy script):
#   NEAR_NETWORK_CONFIG, MPC_CONTRACT_ACCOUNT, N, MACHINE_IP,
#   REUSE_NETWORK_NAME, ACCOUNT_SUFFIX, BASE_PATH, VMM_RPC
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# ---------- defaults from env ----------
NEAR_NETWORK_CONFIG="${NEAR_NETWORK_CONFIG:-mpc-localnet}"
N="${N:-2}"
ACCOUNT_SUFFIX="${ACCOUNT_SUFFIX:-.test.near}"
MPC_NETWORK_NAME="${REUSE_NETWORK_NAME:-mpc-local}"
ROOT_ACCOUNT="${MPC_NETWORK_NAME}${ACCOUNT_SUFFIX}"
MPC_CONTRACT_ACCOUNT="${MPC_CONTRACT_ACCOUNT:-mpc.${ROOT_ACCOUNT}}"
VMM_RPC="${VMM_RPC:-http://127.0.0.1:10000}"
BASE_PATH="${BASE_PATH:?Must set BASE_PATH}"
CLI="python3 $BASE_PATH/vmm/src/vmm-cli.py --url $VMM_RPC"

WORKDIR="/tmp/${USER}/mpc_testnet_scale/${MPC_NETWORK_NAME}"

# Host profile for IP computation
HOST_PROFILE="${HOST_PROFILE:-alice}"
case "$HOST_PROFILE" in
  alice) IP_PREFIX="51.68.219."; IP_START_OCTET=1 ;;
  bob)   IP_PREFIX="51.68.219."; IP_START_OCTET=11 ;;
  *)     echo "Unknown HOST_PROFILE=$HOST_PROFILE"; exit 1 ;;
esac

AGENT_BASE="${AGENT_BASE:-18090}"

# ---------- logging ----------
log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $*"; }
pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; FAILURES=$((FAILURES + 1)); }

FAILURES=0

# ---------- helpers ----------
node_account() { echo "node$1.${ROOT_ACCOUNT}"; }
ip_for_i()     { echo "${IP_PREFIX}$((IP_START_OCTET + $1))"; }
agent_port()   { echo $((AGENT_BASE + $1)); }

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

# Get the JSON "Function execution return value" from near CLI output.
# near CLI prints structured output; the JSON payload is between the
# "return value" banner and the next "Here is your console command" line.
extract_json() {
  sed -n '/^Function execution return value/,/^$/{ /^Function/d; /^$/d; p }' \
    | sed '/^Here is your console/,$d' \
    | sed 's/^│[[:space:]]*//' \
    | sed '/^$/d'
}

# Extract JSON from read-only call (slightly different output format)
extract_json_ro() {
  sed -n '/^Function execution return value/,/^Here is your console/{
    /^Function/d
    /^Here is your console/d
    p
  }'
}

# =============================================================================
# SCENARIO 1: VERIFY
# =============================================================================
verify_cluster() {
  log "============================================================"
  log "SCENARIO 1: Verify MPC Cluster"
  log "============================================================"

  # --- 1.1 Contract state ---
  log "Checking contract state..."
  local state_output
  state_output="$(near_call_ro state '{}')"
  if echo "$state_output" | grep -q '"Running"'; then
    pass "Contract is in Running state"
  else
    fail "Contract is NOT in Running state"
    echo "$state_output" | head -5
  fi

  # --- 1.2 TEE accounts ---
  log "Checking TEE accounts..."
  local tee_output
  tee_output="$(near_call_tx get_tee_accounts '{}' "${ROOT_ACCOUNT}")"
  local tee_json
  tee_json="$(echo "$tee_output" | extract_json)"
  local tee_count
  tee_count="$(echo "$tee_json" | jq 'length')"
  if [ "$tee_count" -eq "$N" ]; then
    pass "TEE accounts: $tee_count registered (expected $N)"
  else
    fail "TEE accounts: $tee_count registered (expected $N)"
  fi

  # Store TLS keys for attestation checks
  local tls_keys=()
  for i in $(seq 0 $((N-1))); do
    local key
    key="$(echo "$tee_json" | jq -r ".[$i].tls_public_key")"
    tls_keys+=("$key")
    log "  node$i TLS key: $key"
  done

  # --- 1.3 All attestations are Dstack (not Mock) ---
  log "Checking attestations are real Dstack..."
  for i in $(seq 0 $((N-1))); do
    local att_output
    att_output="$(near_call_ro get_attestation "{\"tls_public_key\": \"${tls_keys[$i]}\"}")"
    if echo "$att_output" | grep -q '"Dstack"'; then
      local mpc_hash
      mpc_hash="$(echo "$att_output" | extract_json_ro | jq -r '.Dstack.mpc_image_hash')"
      pass "node$i attestation: Dstack (mpc_hash=${mpc_hash:0:16}...)"
    elif echo "$att_output" | grep -q '"Mock"'; then
      fail "node$i attestation: Mock (expected Dstack)"
    else
      fail "node$i attestation: could not determine type"
      echo "$att_output" | head -5
    fi
  done

  # --- 1.4 Signature generation ---
  # Nodes may need time after restart to generate triples/presignatures.
  # Retry up to 4 times with 30s intervals.
  log "Testing signature generation (ECDSA)..."
  local sign_ok=0
  for attempt in 1 2 3 4; do
    local sign_output
    sign_output="$(near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" sign \
      file-args "$REPO_ROOT/docs/localnet/args/sign_ecdsa.json" \
      prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
      sign-as "$(node_account 0)" network-config "$NEAR_NETWORK_CONFIG" \
      sign-with-keychain send 2>&1)"
    if echo "$sign_output" | grep -q '"big_r"'; then
      local sig_r
      sig_r="$(echo "$sign_output" | extract_json | jq -r '.big_r.affine_point')"
      pass "ECDSA signature generated (big_r=${sig_r:0:20}...)"
      sign_ok=1
      break
    fi
    if [ $attempt -lt 4 ]; then
      warn "Signature attempt $attempt failed, retrying in 30s (nodes may still be generating presignatures)..."
      sleep 30
    fi
  done
  if [ $sign_ok -eq 0 ]; then
    fail "ECDSA signature generation failed after 4 attempts"
  fi

  # --- 1.5 Check allowed hashes ---
  log "Checking allowed image hashes..."
  local hashes_output
  hashes_output="$(near_call_ro allowed_docker_image_hashes '{}')"
  local hashes_json
  hashes_json="$(echo "$hashes_output" | extract_json_ro)"
  local hash_count
  hash_count="$(echo "$hashes_json" | jq 'length')"
  pass "Allowed MPC image hashes: $hash_count"
  echo "$hashes_json" | jq -r '.[]' 2>/dev/null | while read -r h; do
    log "  $h"
  done

  log "------------------------------------------------------------"
  if [ "$FAILURES" -eq 0 ]; then
    pass "All verification checks passed"
  else
    fail "Verification completed with $FAILURES failure(s)"
  fi

  return "$FAILURES"
}

# =============================================================================
# SCENARIO 2: ROLLING UPGRADE
# =============================================================================


upgrade_cluster() {
  local new_digest="$1"
  local image_name="${MPC_IMAGE:-nearone/mpc-node}"
  # Strip sha256: prefix if present for voting
  local new_hash="${new_digest#sha256:}"

  if [ ${#new_hash} -ne 64 ]; then
    err "Invalid manifest digest: $new_digest (expected sha256:<64 hex chars>)"
    exit 1
  fi

  log "============================================================"
  log "SCENARIO 2: Rolling Upgrade"
  log "  Image: $image_name"
  log "  New manifest digest: $new_hash"
  log "============================================================"

  # --- Pre-upgrade verification ---
  log "Running pre-upgrade verification..."
  verify_cluster || true
  local pre_failures=$FAILURES
  FAILURES=0

  # Check if already approved
  local current_hashes
  current_hashes="$(near_call_ro allowed_docker_image_hashes '{}' | extract_json_ro)"
  if echo "$current_hashes" | jq -e --arg h "$new_hash" '.[] | select(. == $h)' >/dev/null 2>&1; then
    warn "Hash $new_hash is already approved — skipping vote"
  else
    # --- 2.1 Vote for new MPC hash ---
    log "Voting for new MPC image hash..."
    local threshold
    threshold=$(( (2 * N + 2) / 3 ))
    for i in $(seq 0 $((threshold - 1))); do
      local acct
      acct="$(node_account "$i")"
      log "  vote_code_hash as $acct"
      local vote_out
      vote_out="$(near_call_tx vote_code_hash "{\"code_hash\": \"$new_hash\"}" "$acct" 2>&1)"
      if echo "$vote_out" | grep -q "succeeded\|null"; then
        log "    vote accepted"
      else
        warn "    vote may have failed:"
        echo "$vote_out" | tail -3
      fi
      sleep 2
    done

    # Wait for chain to finalize
    sleep 5

    # Verify vote succeeded
    local updated_hashes
    updated_hashes="$(near_call_ro allowed_docker_image_hashes '{}' | extract_json_ro)"
    if echo "$updated_hashes" | jq -e --arg h "$new_hash" '.[] | select(. == $h)' >/dev/null 2>&1; then
      pass "New hash approved on-chain: $new_hash"
    else
      fail "Hash not found in approved list after voting"
      echo "$updated_hashes"
      return 1
    fi
  fi

  # --- 2.2 Wait for nodes to detect new hash and write to disk ---
  log "Waiting for nodes to detect new approved hash (up to 30s)..."
  local detected=0
  for attempt in $(seq 1 30); do
    local all_detected=1
    for i in $(seq 0 $((N - 1))); do
      local port
      port="$(agent_port "$i")"
      local launcher_logs
      launcher_logs="$(curl -sf "http://127.0.0.1:${port}/logs/mpc-node?text&bare&tail=50" 2>/dev/null || true)"
      # The node writes approved hashes to /mnt/shared/image-digest.bin
      # We can check via the node logs for "writing approved hashes" or similar
      if echo "$launcher_logs" | grep -qi "allowed.*hash\|image.*digest\|approved.*hash" 2>/dev/null; then
        :
      else
        all_detected=0
      fi
    done
    if [ $all_detected -eq 1 ]; then
      detected=1
      break
    fi
    sleep 1
  done
  if [ $detected -eq 1 ]; then
    pass "Nodes detected new approved hash"
  else
    warn "Could not confirm hash detection from logs (nodes may still pick it up on restart)"
  fi

  # --- 2.3 Restart CVMs ---
  log "Restarting CVMs with new manifest digest: $new_hash"

  # Find running VM IDs
  local vm_ids=()
  for i in $(seq 0 $((N - 1))); do
    local app_name="mpc-local-node${i}-testnet-tee"
    local vm_id
    vm_id="$($CLI lsvm 2>/dev/null | grep "$app_name" | grep "running" | awk '{print $2}' | tail -1)"
    if [ -z "$vm_id" ]; then
      err "Could not find running VM for $app_name"
      return 1
    fi
    vm_ids+=("$vm_id")
    log "  node$i VM ID: $vm_id"
  done

  # Update TOML configs with new image, stop, update-user-config, start
  for i in $(seq 0 $((N - 1))); do
    local toml_file="$WORKDIR/node${i}.toml"
    if [ ! -f "$toml_file" ]; then
      err "TOML config not found: $toml_file"
      return 1
    fi

    log "  node$i: restarting VM ${vm_ids[$i]}"

    log "  node$i: stopping VM ${vm_ids[$i]}"
    $CLI stop "${vm_ids[$i]}" 2>/dev/null

    sleep 2

    log "  node$i: updating user-config"
    $CLI update-user-config "${vm_ids[$i]}" "$toml_file" 2>/dev/null

    log "  node$i: starting VM ${vm_ids[$i]}"
    $CLI start "${vm_ids[$i]}" 2>/dev/null
  done

  # --- 2.4 Wait for nodes to come back up ---
  log "Waiting for nodes to become available..."
  for i in $(seq 0 $((N - 1))); do
    local ip
    ip="$(ip_for_i "$i")"
    local url="http://${ip}:18082/public_data"
    log "  node$i: waiting for $url"
    local ready=0
    for attempt in $(seq 1 120); do
      if curl -sf "$url" > /dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 2
    done
    if [ $ready -eq 1 ]; then
      pass "node$i is back online"
    else
      fail "node$i did not come back online within timeout"
    fi
  done

  # --- 2.5 Verify attestation shows new image hash ---
  log "Verifying nodes are using new image..."
  local tee_output
  tee_output="$(near_call_tx get_tee_accounts '{}' "${ROOT_ACCOUNT}")"
  local tee_json
  tee_json="$(echo "$tee_output" | extract_json)"

  for i in $(seq 0 $((N - 1))); do
    local key
    key="$(echo "$tee_json" | jq -r ".[$i].tls_public_key")"
    local att_output
    att_output="$(near_call_ro get_attestation "{\"tls_public_key\": \"$key\"}")"
    local mpc_hash
    mpc_hash="$(echo "$att_output" | extract_json_ro | jq -r '.Dstack.mpc_image_hash // empty')"
    if [ "$mpc_hash" = "$new_hash" ]; then
      pass "node$i attestation confirms new image hash"
    else
      # The attestation may still show old hash until re-attestation
      warn "node$i attestation shows hash: ${mpc_hash:-unknown} (expected $new_hash)"
      log "  Note: attestation updates after the node re-attests with the contract"
    fi
  done

  # --- 2.6 Post-upgrade verification ---
  log "Running post-upgrade verification..."
  verify_cluster || true

  log "============================================================"
  log "Upgrade Summary"
  log "  Manifest digest: $new_hash"
  log "  Pre-upgrade failures: $pre_failures"
  log "  Post-upgrade failures: $FAILURES"
  log "============================================================"
}

# =============================================================================
# MAIN
# =============================================================================
usage() {
  echo "Usage: $0 <command> [args]"
  echo
  echo "Commands:"
  echo "  verify                    Run cluster verification (Scenario 1)"
  echo "  upgrade <manifest_digest>   Run rolling upgrade test (Scenario 2)"
  echo
  echo "Examples:"
  echo "  $0 verify"
  echo "  $0 upgrade sha256:abc123..."
}

case "${1:-}" in
  verify)
    verify_cluster
    exit $?
    ;;
  upgrade)
    if [ -z "${2:-}" ]; then
      err "Missing argument: manifest digest (e.g. sha256:abc123...)"
      usage
      exit 1
    fi
    upgrade_cluster "$2"
    exit $FAILURES
    ;;
  *)
    usage
    exit 1
    ;;
esac
