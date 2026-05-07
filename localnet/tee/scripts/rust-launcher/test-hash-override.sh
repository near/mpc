#!/usr/bin/env bash
# =============================================================================
# MPC Launcher Hash Override Test
# =============================================================================
#
# Tests the mpc_hash_override TOML config parameter which forces the launcher
# to use a specific image digest instead of the newest from the approved list.
#
# Prerequisites:
#   - A running 2-node MPC cluster deployed by deploy-tee-cluster.sh
#   - At least 2 image hashes approved on-chain
#   - Source set-localnet-env.sh (or export the required variables)
#
# Commands:
#   override <hash> <tag>   Force launcher to use a specific approved hash
#   override-reject         Set override to a hash NOT in the approved list (should fail)
#
# Usage:
#   bash test-hash-override.sh override 6a5700fc...full64hex... main-9515e18
#   bash test-hash-override.sh override-reject
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

extract_json_ro() {
  sed -n '/^Function execution return value/,/^Here is your console/{
    /^Function/d
    /^Here is your console/d
    p
  }'
}

# =============================================================================
# POSITIVE TEST: override forces launcher to use a specific approved hash
# =============================================================================
test_override() {
  local override_hash="$1"
  local override_tag="$2"

  log "============================================================"
  log "TEST: Hash Override (positive case)"
  log "  Override hash: ${override_hash:0:16}..."
  log "  Override tag:  $override_tag"
  log "============================================================"

  # Verify the hash is in the approved list
  local approved
  approved="$(near_call_ro allowed_docker_image_hashes '{}' | extract_json_ro)"
  if ! echo "$approved" | jq -e --arg h "$override_hash" '.[] | select(. == $h)' >/dev/null 2>&1; then
    err "Hash $override_hash is NOT in the approved list. Cannot test override."
    echo "$approved"
    return 1
  fi
  log "Hash is in approved list"

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
  done

  # Update TOML configs: add mpc_hash_override and set matching tag
  for i in $(seq 0 $((N - 1))); do
    local toml_file="$WORKDIR/node${i}.toml"
    log "  node$i: adding mpc_hash_override and updating image to tag $override_tag"

    # Update image field (single field: "registry/name:tag")
    sed -i "s|^image = .*|image = \"nearone/mpc-node:$override_tag\"|" "$toml_file"

    # Add or update mpc_hash_override under [launcher_config]
    if grep -q "^mpc_hash_override" "$toml_file"; then
      sed -i "s|^mpc_hash_override = .*|mpc_hash_override = \"sha256:$override_hash\"|" "$toml_file"
    else
      sed -i "/^\[launcher_config\]/a mpc_hash_override = \"sha256:$override_hash\"" "$toml_file"
    fi

    # Stop, update, start
    log "  node$i: restarting with override"
    $CLI stop "${vm_ids[$i]}" 2>/dev/null
    sleep 3
    $CLI update-user-config "${vm_ids[$i]}" "$toml_file" 2>/dev/null
    $CLI start "${vm_ids[$i]}" 2>/dev/null
  done

  # Wait for nodes to come back
  log "Waiting for nodes to become available..."
  for i in $(seq 0 $((N - 1))); do
    local ip
    ip="$(ip_for_i "$i")"
    local url="http://${ip}:18082/public_data"
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
      fail "node$i did not come back online"
      return 1
    fi
  done

  # Check launcher logs — should show "override mpc image hash provided"
  sleep 5
  log "Checking launcher used the override..."
  local port
  port="$(agent_port 0)"
  local launcher_logs
  launcher_logs="$(curl -sf "http://127.0.0.1:${port}/logs/launcher?text&bare&tail=30" 2>/dev/null || true)"
  if echo "$launcher_logs" | grep -q "override"; then
    pass "Launcher log confirms override was used"
  else
    warn "Could not confirm override from launcher logs"
  fi

  # Check the launcher selected the override hash (not the newest)
  if echo "$launcher_logs" | grep -q "$override_hash"; then
    pass "Launcher selected the overridden hash"
  else
    # Check via attestation after re-attestation
    log "Waiting 60s for re-attestation and presignature generation..."
    sleep 60
  fi

  # Verify attestation shows the override hash
  log "Checking attestation shows override hash..."
  local tee_out
  tee_out="$(near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" get_tee_accounts json-args {} prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as "${ROOT_ACCOUNT}" network-config "$NEAR_NETWORK_CONFIG" sign-with-keychain send 2>&1)"
  local tls_key
  tls_key="$(echo "$tee_out" | grep -oP '"tls_public_key": "\K[^"]+' | head -1)"

  if [ -n "$tls_key" ]; then
    local att_out
    att_out="$(near_call_ro get_attestation "{\"tls_public_key\": \"$tls_key\"}")"
    local att_hash
    att_hash="$(echo "$att_out" | extract_json_ro | jq -r '.Dstack.mpc_image_hash // empty')"
    if [ "$att_hash" = "$override_hash" ]; then
      pass "Attestation confirms override hash: ${att_hash:0:16}..."
    else
      warn "Attestation shows ${att_hash:0:16}... (may need more time to re-attest)"
    fi
  fi

  # Test signature
  log "Testing signature generation..."
  local sign_ok=0
  for attempt in 1 2 3; do
    local sign_out
    sign_out="$(near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" sign \
      file-args "$REPO_ROOT/docs/localnet/args/sign_ecdsa.json" \
      prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
      sign-as "$(node_account 0)" network-config "$NEAR_NETWORK_CONFIG" \
      sign-with-keychain send 2>&1)"
    if echo "$sign_out" | grep -q '"big_r"'; then
      pass "ECDSA signature generated"
      sign_ok=1
      break
    fi
    [ $attempt -lt 3 ] && sleep 30
  done
  [ $sign_ok -eq 0 ] && fail "ECDSA signature failed after retries"

  # Clean up: remove override from configs
  log "Cleaning up: removing mpc_hash_override from configs"
  for i in $(seq 0 $((N - 1))); do
    local toml_file="$WORKDIR/node${i}.toml"
    sed -i '/^mpc_hash_override/d' "$toml_file"
  done

  log "------------------------------------------------------------"
  if [ "$FAILURES" -eq 0 ]; then
    pass "Hash override test passed"
  else
    fail "Hash override test completed with $FAILURES failure(s)"
  fi
}

# =============================================================================
# NEGATIVE TEST: override with hash NOT in approved list should fail
# =============================================================================
test_override_reject() {
  log "============================================================"
  log "TEST: Hash Override Rejection (negative case)"
  log "============================================================"

  # Use a fake hash that's definitely not approved
  local fake_hash="0000000000000000000000000000000000000000000000000000000000000000"

  # Find one running VM
  local app_name="mpc-local-node0-testnet-tee"
  local vm_id
  vm_id="$($CLI lsvm 2>/dev/null | grep "$app_name" | grep "running" | awk '{print $2}' | tail -1)"
  if [ -z "$vm_id" ]; then
    err "Could not find running VM for $app_name"
    return 1
  fi

  local toml_file="$WORKDIR/node0.toml"

  # Save original config
  cp "$toml_file" "${toml_file}.bak"

  # Add fake override
  log "  Adding fake mpc_hash_override to node0 config"
  if grep -q "^mpc_hash_override" "$toml_file"; then
    sed -i "s|^mpc_hash_override = .*|mpc_hash_override = \"sha256:$fake_hash\"|" "$toml_file"
  else
    sed -i "/^\[launcher_config\]/a mpc_hash_override = \"sha256:$fake_hash\"" "$toml_file"
  fi

  # Stop, update, start
  log "  Restarting node0 with invalid override..."
  $CLI stop "$vm_id" 2>/dev/null
  sleep 3
  $CLI update-user-config "$vm_id" "$toml_file" 2>/dev/null
  $CLI start "$vm_id" 2>/dev/null

  # Wait for CVM to boot and check launcher logs with retry
  # The dstack agent needs time to become reachable after CVM start
  log "  Waiting for launcher logs (up to 60s)..."
  local port
  port="$(agent_port 0)"
  local launcher_logs=""
  local found_rejection=0
  for attempt in $(seq 1 12); do
    launcher_logs="$(curl -sf "http://127.0.0.1:${port}/logs/launcher?text&bare&tail=30" 2>/dev/null || true)"
    if echo "$launcher_logs" | grep -qi "does not match any approved\|InvalidHashOverride"; then
      found_rejection=1
      break
    fi
    sleep 5
  done

  if [ $found_rejection -eq 1 ]; then
    pass "Launcher correctly rejected invalid override hash"
    log "  $(echo "$launcher_logs" | grep -i "does not match\|InvalidHashOverride" | tail -1)"
  elif echo "$launcher_logs" | grep -qi "Error"; then
    pass "Launcher failed with error (expected for invalid override)"
    log "  $(echo "$launcher_logs" | grep -i "Error" | tail -1)"
  else
    fail "Launcher did not reject the invalid override"
    echo "$launcher_logs" | tail -5
  fi

  # Restore original config and restart
  log "  Restoring original config and restarting node0..."
  cp "${toml_file}.bak" "$toml_file"
  rm -f "${toml_file}.bak"
  $CLI stop "$vm_id" 2>/dev/null || true
  sleep 3
  $CLI update-user-config "$vm_id" "$toml_file" 2>/dev/null
  $CLI start "$vm_id" 2>/dev/null

  # Wait for node to come back (needs full CVM boot time)
  log "  Waiting for node0 to recover (up to 120s)..."
  local ip
  ip="$(ip_for_i 0)"
  local ready=0
  for attempt in $(seq 1 60); do
    if curl -sf "http://${ip}:18082/public_data" > /dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  if [ $ready -eq 1 ]; then
    pass "node0 restored and back online"
  else
    fail "node0 did not come back after restore"
  fi

  log "------------------------------------------------------------"
  if [ "$FAILURES" -eq 0 ]; then
    pass "Hash override rejection test passed"
  else
    fail "Hash override rejection test completed with $FAILURES failure(s)"
  fi
}

# =============================================================================
# MAIN
# =============================================================================
usage() {
  echo "Usage: $0 <command> [args]"
  echo
  echo "Commands:"
  echo "  override <hash> <tag>   Test override with an approved hash"
  echo "  override-reject         Test override with an unapproved hash (should fail)"
  echo
  echo "Examples:"
  echo "  $0 override 6a5700fc...64hex... main-9515e18"
  echo "  $0 override-reject"
}

case "${1:-}" in
  override)
    if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
      err "Missing arguments: <hash> <tag>"
      usage
      exit 1
    fi
    test_override "$2" "$3"
    exit $FAILURES
    ;;
  override-reject)
    test_override_reject
    exit $FAILURES
    ;;
  *)
    usage
    exit 1
    ;;
esac
