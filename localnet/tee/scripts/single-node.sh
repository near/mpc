#!/usr/bin/env bash
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

# Pretty-print JSON but keep arrays of primitives (e.g. byte arrays) on one line.
format_json() {
  python3 -c '
import json, sys

def fmt(obj, indent=2, level=0):
    sp = " " * indent * level
    sp1 = " " * indent * (level + 1)
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        items = []
        for k, v in obj.items():
            items.append(sp1 + json.dumps(k) + ": " + fmt(v, indent, level + 1))
        return "{\n" + ",\n".join(items) + "\n" + sp + "}"
    elif isinstance(obj, list):
        if not obj:
            return "[]"
        if all(not isinstance(i, (dict, list)) for i in obj):
            return json.dumps(obj, separators=(", ", ": "))
        items = []
        for v in obj:
            items.append(sp1 + fmt(v, indent, level + 1))
        return "[\n" + ",\n".join(items) + "\n" + sp + "]"
    else:
        return json.dumps(obj)

print(fmt(json.load(sys.stdin)))
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

VALIDATOR_KEY="$(jq -r .secret_key ~/.near/mpc-localnet/validator_key.json)"

# --- Required ---
: "${BASE_PATH:?Set BASE_PATH (dstack base path)}"
: "${MACHINE_IP:?Set MACHINE_IP (host IP reachable from the CVM)}"
: "${MPC_IMAGE_TAGS:?Set MPC_IMAGE_TAGS}"

# NODE_IP usually equals MACHINE_IP for single-node
NODE_IP="${NODE_IP:-$MACHINE_IP}"

# --- Defaults ---
NEAR_NETWORK_CONFIG="${NEAR_NETWORK_CONFIG:-mpc-localnet}"
FUNDER_ACCOUNT="${FUNDER_ACCOUNT:-test.near}"
NODE_ACCOUNT="${NODE_ACCOUNT:-frodo.test.near}"
CONTRACT_ACCOUNT="${CONTRACT_ACCOUNT:-mpc-contract.test.near}"
NODE_INITIAL_BALANCE="${NODE_INITIAL_BALANCE:-100 NEAR}"

# Ports – auto-pick free ports to avoid conflicts with other services.
# Override any of these via environment variables if you need fixed values.
NEAR_P2P_PORT="${NEAR_P2P_PORT:-24566}"
PUBLIC_DATA_PORT="${PUBLIC_DATA_PORT:-$(find_free_port)}"
STATE_SYNC_PORT="${STATE_SYNC_PORT:-$(find_free_port)}"
MAIN_PORT="${MAIN_PORT:-$(find_free_port)}"
FUTURE_PORT="${FUTURE_PORT:-$(find_free_port)}"

# Host-local ports
SSH_PORT="${SSH_PORT:-$(find_free_port)}"
AGENT_PORT="${AGENT_PORT:-$(find_free_port)}"
LOCAL_DEBUG_PORT="${LOCAL_DEBUG_PORT:-$(find_free_port)}"

# dstack
VMM_RPC="${VMM_RPC:-http://127.0.0.1:10000}"
OS_IMAGE="${OS_IMAGE:-dstack-dev-0.5.4}"
SEALING_KEY_TYPE="${SEALING_KEY_TYPE:-SGX}"
DISK="${DISK:-500G}"

# Paths
REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
TEE_LAUNCHER_DIR="$REPO_ROOT/tee_launcher"
ENV_TPL="${ENV_TPL:-$REPO_ROOT/localnet/tee/scripts/node.env.tpl}"
CONF_TPL="${CONF_TPL:-$REPO_ROOT/localnet/tee/scripts/node.conf.localnet.tpl}"

WORKDIR="${WORKDIR:-$(mktemp -d /tmp/mpc_localnet_one_node.XXXXXX)}"
mkdir -p "$WORKDIR"
log "Work directory: $WORKDIR"
ENV_OUT="$WORKDIR/node.env"
CONF_OUT="$WORKDIR/node.conf"
PUBLIC_DATA_JSON_OUT="${PUBLIC_DATA_JSON_OUT:-$WORKDIR/public_data.json}"

near_account_exists() {
  near account view-account-summary "$1" network-config "$NEAR_NETWORK_CONFIG" now >/dev/null 2>&1
}

create_node_account() {
  if near_account_exists "$NODE_ACCOUNT"; then
    log "NEAR node account exists: $NODE_ACCOUNT"
    return 0
  fi
  log "Creating NEAR node account: $NODE_ACCOUNT (payer=$FUNDER_ACCOUNT, balance=$NODE_INITIAL_BALANCE)"
  near account create-account fund-myself "$NODE_ACCOUNT" "$NODE_INITIAL_BALANCE" \
    autogenerate-new-keypair save-to-keychain \
    sign-as "$FUNDER_ACCOUNT" network-config "$NEAR_NETWORK_CONFIG" \
    sign-with-plaintext-private-key "$VALIDATOR_KEY" send
}

render_env_and_conf() {
  # Correct bootnode format for localnet
  local node_pubkey="${NODE_PUBKEY:-$(jq -r .public_key "$HOME/.near/mpc-localnet/node_key.json")}"
  export NEAR_BOOT_NODES="${NEAR_BOOT_NODES:-${node_pubkey}@${MACHINE_IP}:${NEAR_P2P_PORT}}"

  export APP_NAME="${APP_NAME:-mpc-localnet-one-node-$(date +%s)}"
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
  export EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC="${NODE_IP}:${STATE_SYNC_PORT}"
  export EXTERNAL_MPC_MAIN_PORT="${NODE_IP}:${MAIN_PORT}"
  export EXTERNAL_MPC_FUTURE_PORT="${NODE_IP}:${FUTURE_PORT}"

  export INTERNAL_MPC_PUBLIC_DEBUG_PORT="${INTERNAL_PUBLIC_DEBUG_PORT:-8080}"
  export INTERNAL_MPC_DECENTRALIZED_STATE_SYNC="${INTERNAL_STATE_SYNC_PORT:-24567}"
  export INTERNAL_MPC_MAIN_PORT="${INTERNAL_MAIN_PORT:-80}"
  export INTERNAL_MPC_FUTURE_PORT="${INTERNAL_FUTURE_PORT:-13001}"

  export MPC_ENV="${MPC_ENV:-mpc-localnet}"
  export MPC_IMAGE_NAME="nearone/mpc-node"
  export MPC_IMAGE_TAGS
  export MPC_REGISTRY="registry.hub.docker.com"
  export MPC_ACCOUNT_ID="$NODE_ACCOUNT"
  export MPC_CONTRACT_ID="$CONTRACT_ACCOUNT"
  export MPC_SECRET_STORE_KEY="${MPC_SECRET_STORE_KEY:-00000000000000000000000000000000}"
  export PORTS="${PORTS:-8080:8080,24566:24566,${FUTURE_PORT}:${FUTURE_PORT}}"

  envsubst <"$ENV_TPL" >"$ENV_OUT"
  envsubst <"$CONF_TPL" >"$CONF_OUT"

  log "Rendered env/conf in $WORKDIR"
  log "Bootnodes: $NEAR_BOOT_NODES"
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
  # Give the launcher a moment to pull and start the MPC container.
  local max_attempts=30
  for (( i=1; i<=max_attempts; i++ )); do
    local logs
    logs="$(curl -fsS "${logs_url}" 2>/dev/null || true)"

    # Check for signs the MPC container is running
    if echo "$logs" | grep -qi "MPC launched successfully"; then
      log "Launcher started the MPC container successfully."
      return 0
    fi

    # Check for fatal errors that mean it won't recover
    if echo "$logs" | grep -qi "no such image\|pull.*error\|fatal\|exited with code"; then
      err "Launcher failed to start the MPC container. Last launcher logs:"
      echo "$logs" >&2
      return 1
    fi

    sleep 5
  done

  # Timed out — dump whatever logs we have and let the caller decide
  log "Launcher hasn't confirmed MPC container after $((max_attempts * 5))s. Launcher logs:"
  curl -fsS "${logs_url}" 2>/dev/null || true
  log "Continuing to fetch /public_data (the node may still be starting) ..."
}

fetch_public_data() {
  local url="http://${NODE_IP}:${PUBLIC_DATA_PORT}/public_data"
  log "Fetching /public_data -> $PUBLIC_DATA_JSON_OUT"
  if ! curl -fs --retry 120 --retry-delay 2 --retry-all-errors "$url" 2>/dev/null | format_json > "$PUBLIC_DATA_JSON_OUT"; then
    err "Failed to fetch /public_data from $url"
    err "Debugging hints:"
    err "  - Launcher logs: curl http://127.0.0.1:${AGENT_PORT}/logs/launcher?text&bare&timestamps&tail=40"
    err "  - Rendered env file:  $ENV_OUT"
    err "  - Rendered conf file: $CONF_OUT"
    err "  - CVM app name: $APP_NAME"
    return 1
  fi
  log "Saved JSON: $PUBLIC_DATA_JSON_OUT"
}

# --- Main ---
create_node_account
render_env_and_conf

deploy_one_node
echo "$APP_NAME" > "$WORKDIR/app_name"
log "Saved app name to $WORKDIR/app_name"

wait_for_launcher
fetch_public_data

log "Done"
log "To remove the CVM later:  bash $0 --cleanup $WORKDIR"
