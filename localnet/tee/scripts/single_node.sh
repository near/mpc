#!/usr/bin/env bash
set -euo pipefail
export NEAR_CLI_DISABLE_SPINNER=1
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

# Ports (only the ones you actually use)
NEAR_P2P_PORT="${NEAR_P2P_PORT:-24566}"
PUBLIC_DATA_PORT="${PUBLIC_DATA_PORT:-18082}"
STATE_SYNC_PORT="${STATE_SYNC_PORT:-24567}"
MAIN_PORT="${MAIN_PORT:-80}"
FUTURE_PORT="${FUTURE_PORT:-13001}"

# Host-local ports (avoid tcp:: in vmm-cli)
SSH_PORT="${SSH_PORT:-1220}"
AGENT_PORT="${AGENT_PORT:-18090}"
LOCAL_DEBUG_PORT="${LOCAL_DEBUG_PORT:-3031}"

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

WORKDIR="${WORKDIR:-/tmp/$USER/mpc_localnet_one_node}"
mkdir -p "$WORKDIR"
ENV_OUT="$WORKDIR/node.env"
CONF_OUT="$WORKDIR/node.conf"
PUBLIC_DATA_JSON_OUT="${PUBLIC_DATA_JSON_OUT:-$WORKDIR/public_data.json}"

log(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }

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
  NODE_PUBKEY="${NODE_PUBKEY:-$(jq -r .public_key "$HOME/.near/mpc-localnet/node_key.json")}"
  export NEAR_BOOT_NODES="${NEAR_BOOT_NODES:-${NODE_PUBKEY}@${MACHINE_IP}:${NEAR_P2P_PORT}}"

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
  log "Deploying dstack CVM app: $APP_NAME"
  ( cd "$TEE_LAUNCHER_DIR" && ./deploy-launcher.sh --yes --env-file "$ENV_OUT" --base-path "$BASE_PATH" --python-exec python )
}

fetch_public_data() {
  local url="http://${NODE_IP}:${PUBLIC_DATA_PORT}/public_data"
  log "Fetching /public_data -> $PUBLIC_DATA_JSON_OUT"
  curl -fsS --retry 120 --retry-delay 2 --retry-all-errors "$url" | jq . > "$PUBLIC_DATA_JSON_OUT"
  log "Saved JSON: $PUBLIC_DATA_JSON_OUT"
}

create_node_account
render_env_and_conf
deploy_one_node
fetch_public_data
log "✅ Done"
