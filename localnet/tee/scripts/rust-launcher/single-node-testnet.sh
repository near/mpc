#!/usr/bin/env bash
# Adaptation of single-node.sh for testnet — for testing PR #3145 (DSS fix).
#
# Differences from single-node.sh:
#  - chain_id = testnet (not localnet)
#  - No NEAR account creation (uses dummy account ID — DSS doesn't care)
#  - Boot nodes fetched from testnet RPC, not localnet validator
#  - Threads tier3_public_addr + external_storage_fallback_threshold from
#    PR #3145 into the launcher TOML
#  - Genesis is downloaded from testnet (no embedded local genesis)
#
# Required env:
#   BASE_PATH       — dstack base path (e.g. /mnt/data/barak/dstack_latest/meta-dstack/dstack)
#   MACHINE_IP      — host IP reachable from the CVM (one of the static IPs)
#   MPC_IMAGE_TAG   — custom mpc-node image tag built from PR #3145
#                     (e.g. "barak-testing-dss-tier3-public-addr-c371677")
#
# Optional env:
#   TIER3_PUBLIC_ADDR     — defaults to ${MACHINE_IP}:${STATE_SYNC_PORT}
#   FALLBACK_THRESHOLD    — defaults to 1000 (DSS-first with bucket safety net)
#   FORCE_BIND_TO_IP      — if "1", bind network.addr to the same specific IP
#                           (mirrors Bob's setup for true reproduction)
#
set -euo pipefail
export NEAR_CLI_DISABLE_SPINNER=1

log(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }

find_free_port() {
  python3 -c '
import socket, random
while True:
    port = random.randint(12000, 24000)
    try:
        s = socket.socket()
        s.bind(("", port))
        s.close()
        print(port)
        break
    except OSError:
        continue
'
}

remove_cvm_app() {
  local name_file="$1"
  if [ ! -f "$name_file" ]; then
    err "No app name file found at $name_file"
    return 1
  fi
  local name
  name="$(cat "$name_file")"
  log "Looking up VM ID for $name ..."
  local vm_id
  vm_id="$(python3 "$BASE_PATH/vmm/src/vmm-cli.py" --url "$VMM_RPC" lsvm 2>/dev/null \
    | grep "$name" | awk -F'│' '{gsub(/ /,"",$2); print $2}' | head -1)"
  if [ -n "$vm_id" ]; then
    log "Stopping CVM app: $name (vm_id=$vm_id)"
    python3 "$BASE_PATH/vmm/src/vmm-cli.py" --url "$VMM_RPC" stop "$vm_id" 2>/dev/null || true
    log "Waiting for VM to stop ..."
    for (( i=1; i<=30; i++ )); do
      if python3 "$BASE_PATH/vmm/src/vmm-cli.py" --url "$VMM_RPC" lsvm 2>/dev/null \
          | grep "$vm_id" | grep -q "stopped"; then
        break
      fi
      sleep 2
    done
    log "Removing CVM app: $name (vm_id=$vm_id)"
    python3 "$BASE_PATH/vmm/src/vmm-cli.py" --url "$VMM_RPC" remove "$vm_id"
  else
    err "No VM found for $name"
    return 1
  fi
}

# --- Cleanup mode (only needs BASE_PATH) ---
if [ "${1:-}" = "--cleanup" ]; then
  : "${BASE_PATH:?Set BASE_PATH (dstack base path)}"
  VMM_RPC="${VMM_RPC:-http://127.0.0.1:10000}"
  workdir="${2:?Usage: $0 --cleanup <WORKDIR>}"
  remove_cvm_app "$workdir/app_name"
  exit $?
fi

# --- Required ---
: "${BASE_PATH:?Set BASE_PATH (dstack base path)}"
: "${MACHINE_IP:?Set MACHINE_IP (one of the static host IPs)}"
: "${MPC_IMAGE_TAG:?Set MPC_IMAGE_TAG (custom image built from PR #3145, e.g. barak-testing-...)}"

NODE_IP="${NODE_IP:-$MACHINE_IP}"

# --- Defaults ---
NODE_ACCOUNT="${NODE_ACCOUNT:-dss-test.testnet}"        # dummy — DSS doesn't care
CONTRACT_ACCOUNT="${CONTRACT_ACCOUNT:-v1.signer-prod.testnet}"  # real testnet contract — drives shard tracking

# Ports — auto-pick free ports.
PUBLIC_DATA_PORT="${PUBLIC_DATA_PORT:-$(find_free_port)}"
STATE_SYNC_PORT="${STATE_SYNC_PORT:-24567}"             # nearcore default; needs to match peers' expectations
MAIN_PORT="${MAIN_PORT:-$(find_free_port)}"
FUTURE_PORT="${FUTURE_PORT:-$(find_free_port)}"
SSH_PORT="${SSH_PORT:-$(find_free_port)}"
AGENT_PORT="${AGENT_PORT:-$(find_free_port)}"
LOCAL_DEBUG_PORT="${LOCAL_DEBUG_PORT:-$(find_free_port)}"

# --- PR #3145 fields under test ---
# TIER3_PUBLIC_ADDR: explicitly empty/unset = omit from TOML (test Option 3b
# without the application-level fix). Default = MACHINE_IP:STATE_SYNC_PORT
# (matches Bob's setup, exercises PR #3145).
TIER3_PUBLIC_ADDR="${TIER3_PUBLIC_ADDR-${MACHINE_IP}:${STATE_SYNC_PORT}}"
FALLBACK_THRESHOLD="${FALLBACK_THRESHOLD:-1000}"

# dstack
VMM_RPC="${VMM_RPC:-http://127.0.0.1:10000}"
OS_IMAGE="${OS_IMAGE:-dstack-dev-0.5.8}"
SEALING_KEY_TYPE="${SEALING_KEY_TYPE:-SGX}"   # SGX = local key provider, no external KMS dep
DISK="${DISK:-500G}"

# Paths
REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
TEE_LAUNCHER_DIR="$REPO_ROOT/deployment/cvm-deployment"
ENV_TPL="${ENV_TPL:-$REPO_ROOT/localnet/tee/scripts/node.env.tpl}"
CONF_TPL="${CONF_TPL:-$REPO_ROOT/localnet/tee/scripts/rust-launcher/node.conf.testnet.toml.tpl}"

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

WORKDIR="${WORKDIR:-$(mktemp -d /tmp/mpc_testnet_dss.XXXXXX)}"
mkdir -p "$WORKDIR"
log "Work directory: $WORKDIR"
ENV_OUT="$WORKDIR/node.env"
CONF_OUT="$WORKDIR/node.toml"
PUBLIC_DATA_JSON_OUT="${PUBLIC_DATA_JSON_OUT:-$WORKDIR/public_data.json}"

fetch_testnet_bootnodes() {
  curl -s -X POST https://rpc.testnet.near.org \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"network_info","params":[],"id":"x"}' \
  | jq -r '.result.active_peers[] | "\(.id)@\(.addr)"' \
  | awk -F'@' '!seen[$2]++ {print $0}' \
  | paste -sd',' -
}

render_env_and_conf() {
  log "Fetching testnet boot nodes ..."
  export NEAR_BOOT_NODES="${NEAR_BOOT_NODES:-$(fetch_testnet_bootnodes)}"
  log "Got $(echo "$NEAR_BOOT_NODES" | tr ',' '\n' | wc -l) boot nodes"

  export APP_NAME="${APP_NAME:-mpc-testnet-dss-$(date +%s)}"
  export VMM_RPC OS_IMAGE SEALING_KEY_TYPE DISK
  export DOCKER_COMPOSE_FILE_PATH="launcher_docker_compose.yaml"
  export USER_CONFIG_FILE_PATH="$CONF_OUT"

  export EXTERNAL_SSH_PORT="127.0.0.1:${SSH_PORT}"
  export EXTERNAL_DSTACK_AGENT_PORT="127.0.0.1:${AGENT_PORT}"
  export EXTERNAL_MPC_LOCAL_DEBUG_PORT="127.0.0.1:${LOCAL_DEBUG_PORT}"

  export INTERNAL_SSH_PORT="${INTERNAL_SSH_PORT:-22}"
  export INTERNAL_DSTACK_AGENT_PORT="${INTERNAL_DSTACK_AGENT_PORT:-8090}"
  export INTERNAL_MPC_LOCAL_DEBUG_PORT="${INTERNAL_MPC_LOCAL_DEBUG_PORT:-3030}"

  export EXTERNAL_MPC_PUBLIC_DEBUG_PORT="${NODE_IP}:${PUBLIC_DATA_PORT}"
  # CRITICAL: bind state sync port to the specific NODE_IP (not 0.0.0.0) so we
  # genuinely test the multi-IP-host scenario from #1734.
  export EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC="${NODE_IP}:${STATE_SYNC_PORT}"
  export EXTERNAL_MPC_MAIN_PORT="${NODE_IP}:${MAIN_PORT}"
  export EXTERNAL_MPC_FUTURE_PORT="${NODE_IP}:${FUTURE_PORT}"

  export INTERNAL_MPC_PUBLIC_DEBUG_PORT="${INTERNAL_PUBLIC_DEBUG_PORT:-8080}"
  export INTERNAL_MPC_DECENTRALIZED_STATE_SYNC="${INTERNAL_STATE_SYNC_PORT:-24567}"
  export INTERNAL_MPC_MAIN_PORT="${INTERNAL_MAIN_PORT:-80}"
  export INTERNAL_MPC_FUTURE_PORT="${INTERNAL_FUTURE_PORT:-13001}"

  export MPC_IMAGE="nearone/mpc-node"
  export MPC_ACCOUNT_ID="$NODE_ACCOUNT"
  export MPC_CONTRACT_ID="$CONTRACT_ACCOUNT"
  export MPC_SECRET_STORE_KEY="${MPC_SECRET_STORE_KEY:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}"

  export TIER3_PUBLIC_ADDR FALLBACK_THRESHOLD

  export PORTS="${PORTS:-8080:8080,${STATE_SYNC_PORT}:${STATE_SYNC_PORT}}"
  export PORTS_TOML
  PORTS_TOML="$(ports_to_toml "$PORTS")"

  envsubst <"$ENV_TPL" >"$ENV_OUT"
  envsubst <"$CONF_TPL" >"$CONF_OUT"

  # If TIER3_PUBLIC_ADDR is empty (i.e. operator opted out so we can test
  # host-level fixes like Option 3b in isolation), drop the rendered line —
  # neard rejects an empty SocketAddr.
  if [ -z "$TIER3_PUBLIC_ADDR" ]; then
    sed -i '/^tier3_public_addr = ""/d' "$CONF_OUT"
  fi

  log "Rendered env/conf in $WORKDIR"
  log "tier3_public_addr: ${TIER3_PUBLIC_ADDR:-<unset — host-level fix expected>}"
  log "external_storage_fallback_threshold: $FALLBACK_THRESHOLD"
  log "Image tag: $MPC_IMAGE_TAG"
}

deploy_one_node() {
  local deploy_log="$WORKDIR/deploy.log"
  log "Deploying dstack CVM app: $APP_NAME (log: $deploy_log)"
  if ! ( cd "$TEE_LAUNCHER_DIR" && ./deploy-launcher.sh --yes --env-file "$ENV_OUT" --base-path "$BASE_PATH" --python-exec python ) > "$deploy_log" 2>&1; then
    err "deploy-launcher.sh failed. Output:"
    cat "$deploy_log" >&2
    return 1
  fi
}

wait_for_launcher() {
  local agent_url="http://127.0.0.1:${AGENT_PORT}"
  local logs_url="${agent_url}/logs/launcher?text&bare&timestamps&tail=20"

  log "Waiting for dstack agent to become reachable at ${agent_url} ..."
  if ! curl -fsS --retry 60 --retry-delay 2 --retry-all-errors "${agent_url}/" >/dev/null 2>&1; then
    err "dstack agent never became reachable at ${agent_url}"
    return 1
  fi

  log "Agent is up. Checking launcher logs for MPC container startup ..."
  local max_attempts=60
  for (( i=1; i<=max_attempts; i++ )); do
    local logs
    logs="$(curl -fsS "${logs_url}" 2>/dev/null || true)"

    if echo "$logs" | grep -qi "MPC launched successfully"; then
      log "Launcher started the MPC container successfully."
      return 0
    fi

    if echo "$logs" | grep -qi "no such image\|pull.*error\|fatal\|exited with code"; then
      err "Launcher failed to start the MPC container. Last launcher logs:"
      echo "$logs" >&2
      return 1
    fi

    sleep 5
  done

  log "Launcher hasn't confirmed MPC container after $((max_attempts * 5))s. Launcher logs:"
  curl -fsS "${logs_url}" 2>/dev/null || true
  log "Continuing anyway — node may still be starting (testnet genesis is large) ..."
}

watch_dss_metrics() {
  local metrics_url="http://${NODE_IP}:${PUBLIC_DATA_PORT}/metrics"
  log "Watching DSS metrics at ${metrics_url} (Ctrl+C to stop) ..."
  while true; do
    echo "=== $(date +%T) ==="
    curl -sf --max-time 5 "$metrics_url" 2>/dev/null | grep -E "^near_block_height_head |^near_tier3_public_addr|^near_peer_connections|^near_state_sync_download_result|^near_sync_status" || echo "(metrics not yet reachable)"
    sleep 30
  done
}

# --- Main ---
render_env_and_conf

log "Rendered TOML config (relevant fields):"
grep -E "tier3_public_addr|external_storage_fallback_threshold|chain_id|boot_nodes|network_addr|mpc_contract_id" "$CONF_OUT" || true

deploy_one_node
echo "$APP_NAME" > "$WORKDIR/app_name"
log "Saved app name to $WORKDIR/app_name"

wait_for_launcher

log ""
log "=== Deployment complete ==="
log "Public metrics: http://${NODE_IP}:${PUBLIC_DATA_PORT}/metrics"
log "Launcher logs:  curl http://127.0.0.1:${AGENT_PORT}/logs/launcher?text&bare&timestamps&tail=40"
log "MPC node logs:  curl http://127.0.0.1:${AGENT_PORT}/logs/mpc-node?text&bare&timestamps&tail=40"
log ""
log "Run with WATCH_METRICS=1 to tail DSS metrics, or:"
log "  bash $0 --cleanup $WORKDIR"

if [ "${WATCH_METRICS:-0}" = "1" ]; then
  watch_dss_metrics
fi
