#!/usr/bin/env bash
set -euo pipefail

### =========================
### Fully-automated, resumable MPC testnet TEE deploy (with subaccounts)
### - Avoids faucet 429 by allowing a funded FUNDER_ACCOUNT to create/top-up ROOT
### - Subaccounts are ALWAYS created by ROOT (required by NEAR permission model)
### - Contract created as mpc.<root>, nodes as node{i}.<root>
### - Default funding supports contract (~16 NEAR) + up to 10 nodes (0.3 NEAR ea) + buffer
### - Resume logic + per-phase ENTER prompts
### =========================

### Required inputs
: "${MPC_NETWORK_BASE_NAME:?Must set MPC_NETWORK_BASE_NAME (e.g. export MPC_NETWORK_BASE_NAME=barak-test)}"
: "${N:?Must set N (e.g. export N=10)}"
: "${BASE_PATH:?Must set BASE_PATH to dstack base path (contains vmm/src/vmm-cli.py)}"
: "${MPC_IMAGE_TAGS:?Must set MPC_IMAGE_TAGS (e.g. export MPC_IMAGE_TAGS=3.3.0)}"

# If set, use this funded testnet account instead of faucet to create/top-up the ROOT account.
# Example: export FUNDER_ACCOUNT=barak_tee_test1.testnet
FUNDER_ACCOUNT="${FUNDER_ACCOUNT:-}"

# How much balance to ensure on ROOT (used for creating contract+nodes subaccounts)
# Default supports ~16 NEAR contract + 10 * 0.3 NEAR nodes + ~1 NEAR buffer => 20 NEAR
ROOT_INITIAL_BALANCE="${ROOT_INITIAL_BALANCE:-20 NEAR}"

### Optional controls
ACCOUNT_MODE="${ACCOUNT_MODE:-subaccounts}"   # subaccounts|faucet (faucet is fallback only)

# Initial balances (for subaccounts mode)
CONTRACT_INITIAL_BALANCE="${CONTRACT_INITIAL_BALANCE:-16 NEAR}"
NODE_INITIAL_BALANCE="${NODE_INITIAL_BALANCE:-0.3 NEAR}"

# How many nodes to fund for, even if N is smaller (so you can scale later without re-funding root)
MAX_NODES_TO_FUND="${MAX_NODES_TO_FUND:-10}"

# Faucet retry/backoff (for root creation if FUNDER_ACCOUNT is not set)
FAUCET_MAX_RETRIES="${FAUCET_MAX_RETRIES:-8}"
FAUCET_BACKOFF_BASE_SEC="${FAUCET_BACKOFF_BASE_SEC:-10}"

# Resume behavior
RESUME="${RESUME:-1}"
FORCE_REDEPLOY="${FORCE_REDEPLOY:-0}"
FORCE_RECOLLECT="${FORCE_RECOLLECT:-0}"
FORCE_REINIT_ARGS="${FORCE_REINIT_ARGS:-0}"

# Phase gating
START_FROM_PHASE="${START_FROM_PHASE:-auto}"   # auto recommended
STOP_AFTER_PHASE="${STOP_AFTER_PHASE:-}"

# Pause between phases
NO_PAUSE="${NO_PAUSE:-0}"

# If set, reuse existing network name (and NEAR accounts)
if [ -n "${REUSE_NETWORK_NAME:-}" ]; then
  RAND_SUFFIX="(reused)"
  MPC_NETWORK_NAME="${REUSE_NETWORK_NAME}"
else
  RAND_SUFFIX="$(printf '%04x' $((RANDOM % 65536)))"
  MPC_NETWORK_NAME="${MPC_NETWORK_BASE_NAME}-${RAND_SUFFIX}"
fi

### Constants / defaults
IP_PREFIX="51.68.219."
IP_START_OCTET=1

SSH_BASE=1220
AGENT_BASE=18090
PUBLIC_DATA_BASE=18081
LOCAL_DEBUG_BASE=3031

STATE_SYNC_PORT=24567
MAIN_PORT=80
FUTURE_PORT=13001

INTERNAL_PUBLIC_DEBUG_PORT=8080
INTERNAL_LOCAL_DEBUG_PORT=3030
INTERNAL_STATE_SYNC_PORT=24567
INTERNAL_MAIN_PORT=80
INTERNAL_FUTURE_PORT=13001

OS_IMAGE="${OS_IMAGE:-dstack-dev-0.5.4}"
SEALING_KEY_TYPE="${SEALING_KEY_TYPE:-SGX}"
VMM_RPC="${VMM_RPC:-http://127.0.0.1:10000}"

# Repo-relative paths (assumes you're running from repo root)
REPO_ROOT="$(pwd)"
TEE_LAUNCHER_DIR="$REPO_ROOT/tee_launcher"
COMPOSE_YAML="$TEE_LAUNCHER_DIR/launcher_docker_compose.yaml"
ADD_DOMAIN_JSON="$REPO_ROOT/docs/localnet/args/add_domain.json"

# templates live here (per your layout)
ENV_TPL="$REPO_ROOT/deployment/testnet/scripts/node.env.tpl"
CONF_TPL="$REPO_ROOT/deployment/testnet/scripts/node.conf.tpl"

WORKDIR="/tmp/$USER/mpc_testnet_scale/$MPC_NETWORK_NAME"
mkdir -p "$WORKDIR"

# Derived accounts
ROOT_ACCOUNT="${MPC_NETWORK_NAME}.testnet"

# Subaccount naming (REQUIRED for subaccounts mode)
MPC_CONTRACT_ACCOUNT="mpc.${ROOT_ACCOUNT}"
node_account_for_i() { echo "node$1.${ROOT_ACCOUNT}"; }

# Artifact paths
KEYS_JSON="$WORKDIR/keys.json"
INIT_ARGS_JSON="$WORKDIR/init_args.json"

near_sleep() {
  local reason="${1:-after NEAR tx}"
  log "Sleeping ${NEAR_TX_SLEEP_SEC}s (${reason})"
  sleep "$NEAR_TX_SLEEP_SEC"
}

# ---------- logging ----------
log() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

pause_phase() {
  local name="$1"
  if [ "$NO_PAUSE" = "1" ]; then
    log "NO_PAUSE=1 -> continuing automatically (phase: $name)"
    return 0
  fi
  echo
  echo "------------------------------------------------------------"
  echo "Phase: $name"
  echo "Network: $MPC_NETWORK_NAME"
  echo "Workdir: $WORKDIR"
  echo "Account mode: $ACCOUNT_MODE"
  echo "ROOT_ACCOUNT: $ROOT_ACCOUNT"
  echo "CONTRACT_ACCOUNT: $MPC_CONTRACT_ACCOUNT"
  echo "FUNDER_ACCOUNT: ${FUNDER_ACCOUNT:-<none>}"
  echo "------------------------------------------------------------"
  read -r -p "Press ENTER to continue (or Ctrl+C to abort)..." _
  echo
}

# ---------- helpers ----------
ceil_2n_3() { local n="$1"; echo $(( (2*n + 2) / 3 )); }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

ip_for_i() { echo "${IP_PREFIX}$((IP_START_OCTET + $1))"; }
ssh_port_for_i() { echo $((SSH_BASE + $1)); }
agent_port_for_i() { echo $((AGENT_BASE + $1)); }
public_port_for_i() { echo $((PUBLIC_DATA_BASE + $1)); }
local_dbg_port_for_i() { echo $((LOCAL_DEBUG_BASE + $1)); }

host_has_ip() { local ip="$1"; ip addr show | grep -qE "inet ${ip}/32"; }

port_free() {
  local ip="$1" port="$2"
  local addrs
  addrs="$(ss -H -4 -ltn 2>/dev/null | awk '{print $4}')"
  if echo "$addrs" | grep -Eq "0\.0\.0\.0:${port}$|${ip//./\\.}:${port}$"; then
    return 1
  fi
  return 0
}

file_nonempty() { local p="$1"; [ -f "$p" ] && [ -s "$p" ]; }

maybe_stop_after_phase() {
  local phase="$1"
  if [ -n "$STOP_AFTER_PHASE" ] && [ "$STOP_AFTER_PHASE" = "$phase" ]; then
    warn "STOP_AFTER_PHASE=$STOP_AFTER_PHASE requested. Stopping now."
    exit 0
  fi
}

# ---------- phase gating ----------
phase_rank() {
  case "$1" in
    preflight) echo 10 ;;
    render) echo 20 ;;
    near_accounts) echo 30 ;;
    near_nodes) echo 40 ;;
    near_contract) echo 50 ;;
    deploy) echo 60 ;;
    collect) echo 70 ;;
    init_args) echo 75 ;;
    near_keys) echo 80 ;;
    near_init) echo 90 ;;
    near_vote_hash) echo 95 ;;
    near_vote_domain) echo 96 ;;
    auto) echo 0 ;;
    *) err "Unknown phase name: $1"; exit 1 ;;
  esac
}


should_run_from_start() {
  local phase="$1"
  local start="$START_FROM_PHASE"
  if [ "$start" = "auto" ]; then
    return 0
  fi
  local pr sr
  pr="$(phase_rank "$phase")"
  sr="$(phase_rank "$start")"
  [ "$pr" -ge "$sr" ]
}

compute_auto_start_phase() {
  if [ "$START_FROM_PHASE" != "auto" ]; then
    echo "$START_FROM_PHASE"
    return 0
  fi
  if [ "$RESUME" != "1" ]; then
    echo "preflight"
    return 0
  fi
  if file_nonempty "$INIT_ARGS_JSON"; then
    echo "near_keys"
    return 0
  fi
  if file_nonempty "$KEYS_JSON"; then
    echo "init_args"
    return 0
  fi
  echo "preflight"
}

### =========================
### BOOTNODES (DEDUP BY ADDR)
### =========================
fetch_bootnodes() {
  curl -s -X POST https://rpc.testnet.near.org \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc": "2.0", "method": "network_info", "params": [], "id": "dontcare"}' \
  | jq -r '.result.active_peers[] | "\(.id)@\(.addr)"' \
  | awk -F'@' '!seen[$2]++ {print $0}' \
  | paste -sd',' -
}

### =========================
### NEAR helpers (balance, create, topup)
### =========================
near_account_exists() {
  local acct="$1"
  set +e
  NEAR_CLI_DISABLE_SPINNER=1 near account view-account-summary "$acct" network-config testnet now >/dev/null 2>&1
  local rc=$?
  set -e
  [ $rc -eq 0 ]
}

# returns NEAR balance as float string (e.g., "19.1234") or "0" if missing
near_get_balance() {
  local acct="$1"
  # Use RPC directly to avoid near-cli formatting issues
  local resp
  resp="$(curl -s https://rpc.testnet.near.org -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$acct\"}}")"
  if echo "$resp" | jq -e '.error' >/dev/null 2>&1; then
    echo "0"
    return 0
  fi
  local yocto
  yocto="$(echo "$resp" | jq -r '.result.amount')"
  python3 - <<PY
yocto=int("$yocto")
print(yocto/1e24)
PY
}

# parse "<number> NEAR" -> number float
parse_near_amount() {
  local s="$1"
  python3 - <<PY
import re
s="${s}"
m=re.match(r"\s*([0-9]*\.?[0-9]+)\s*NEAR\s*$", s)
if not m:
    raise SystemExit(f"Bad NEAR amount format: {s!r} (expected like '0.3 NEAR')")
print(m.group(1))
PY
}

# compare floats: returns 0 if a < b
float_lt() {
  python3 - <<PY
a=float("${1}")
b=float("${2}")
print(1 if a < b else 0)
PY
}

# compute max(required_contract + max_nodes*node + buffer, ROOT_INITIAL_BALANCE)
required_root_balance() {
  local contract node maxn target
  contract="$(parse_near_amount "$CONTRACT_INITIAL_BALANCE")"
  node="$(parse_near_amount "$NODE_INITIAL_BALANCE")"
  maxn="$MAX_NODES_TO_FUND"
  target="$(parse_near_amount "$ROOT_INITIAL_BALANCE")"
  python3 - <<PY
contract=float("$contract")
node=float("$node")
maxn=int("$maxn")
target=float("$target")
buffer=1.0
req=contract + node*maxn + buffer
print(max(req, target))
PY
}

# best-effort top-up root from funder to reach target balance
topup_root_if_needed() {
  local target
  target="$(required_root_balance)"
  local cur
  cur="$(near_get_balance "$ROOT_ACCOUNT")"
  log "ROOT balance: $cur NEAR, target: $target NEAR (supports contract + up to $MAX_NODES_TO_FUND nodes + buffer)"

  local need
  need="$(python3 - <<PY
cur=float("$cur")
target=float("$target")
delta=target-cur
# add small margin for tx fee
if delta > 0.05:
    print(delta)
else:
    print(0.0)
PY
)"
  if [ "$(float_lt "0.0" "$need")" = "1" ]; then
    if [ -z "$FUNDER_ACCOUNT" ]; then
      err "ROOT needs top-up of ~$need NEAR but FUNDER_ACCOUNT is not set."
      err "Set FUNDER_ACCOUNT=<funded>.testnet or increase ROOT_INITIAL_BALANCE at creation."
      exit 1
    fi
    log "Topping up ROOT from $FUNDER_ACCOUNT by ~${need} NEAR"
    NEAR_CLI_DISABLE_SPINNER=1 near tokens "$FUNDER_ACCOUNT" send-near "$ROOT_ACCOUNT" "${need} NEAR" \
      network-config testnet sign-with-keychain send
    near_sleep "root top-up"
  else
    log "No root top-up needed."
  fi
}

faucet_create_with_retry() {
  local acct="$1"
  if near_account_exists "$acct"; then
    log "account exists: $acct"
    return 0
  fi
  local attempt=1
  local backoff="$FAUCET_BACKOFF_BASE_SEC"
  while [ "$attempt" -le "$FAUCET_MAX_RETRIES" ]; do
    log "faucet create (attempt $attempt/$FAUCET_MAX_RETRIES): $acct"
    set +e
    local out
    out="$(NEAR_CLI_DISABLE_SPINNER=1 near account create-account sponsor-by-faucet-service "$acct" \
      autogenerate-new-keypair save-to-legacy-keychain network-config testnet create 2>&1)"
    local rc=$?
    set -e
    if [ $rc -eq 0 ]; then
      log "faucet create succeeded: $acct"
      return 0
    fi
    if echo "$out" | grep -q "429 Too Many Requests"; then
      warn "faucet 429 for $acct; sleeping ${backoff}s then retry"
      sleep "$backoff"
      backoff=$((backoff * 2))
      attempt=$((attempt + 1))
      continue
    fi
    err "faucet create failed for $acct:"
    echo "$out"
    return 1
  done
  err "faucet create exhausted retries for $acct"
  return 1
}

create_account_fund_myself_if_missing() {
  local new_acct="$1"
  local initial_balance="$2"
  local payer="$3"

  if near_account_exists "$new_acct"; then
    log "account exists: $new_acct"
    return 0
  fi

  log "creating account: $new_acct (balance=$initial_balance) paid by $payer"
  NEAR_CLI_DISABLE_SPINNER=1 near account create-account fund-myself "$new_acct" "$initial_balance" \
    autogenerate-new-keypair save-to-legacy-keychain \
    sign-as "$payer" network-config testnet sign-with-keychain send
  near_sleep "created account $new_acct"
  
}

### =========================
### PRE-FLIGHT
### =========================
preflight() {
  log "Preflight: validating IPs, ports, tools, and files"

  need_cmd ss
  need_cmd envsubst
  need_cmd curl
  need_cmd jq
  need_cmd near
  need_cmd cargo
  need_cmd awk
  need_cmd python3

  [ -d "$TEE_LAUNCHER_DIR" ] || { err "Missing tee_launcher dir at $TEE_LAUNCHER_DIR"; exit 1; }
  [ -f "$COMPOSE_YAML" ] || { err "Missing $COMPOSE_YAML"; exit 1; }
  [ -f "$ADD_DOMAIN_JSON" ] || { err "Missing $ADD_DOMAIN_JSON"; exit 1; }
  [ -f "$ENV_TPL" ] || { err "Missing template $ENV_TPL"; exit 1; }
  [ -f "$CONF_TPL" ] || { err "Missing template $CONF_TPL"; exit 1; }

  log "Using IP range: ${IP_PREFIX}${IP_START_OCTET} .. ${IP_PREFIX}$((IP_START_OCTET + N - 1))"
  log "Ports per node: main=$MAIN_PORT future=$FUTURE_PORT state_sync=$STATE_SYNC_PORT public_data_base=$PUBLIC_DATA_BASE"
  log "Localhost per node: ssh_base=$SSH_BASE agent_base=$AGENT_BASE local_debug_base=$LOCAL_DEBUG_BASE"

  local any_fail=0
  for i in $(seq 0 $((N-1))); do
    local ip; ip="$(ip_for_i "$i")"
    log "node$i: checking IP and ports for $ip"

    if ! host_has_ip "$ip"; then
      err "node$i: IP not configured on host: $ip"
      any_fail=1
      continue
    else
      echo "  ✅ IP exists on host: $ip"
    fi

    local p_pub p_ssh p_agent p_ld
    p_pub="$(public_port_for_i "$i")"
    p_ssh="$(ssh_port_for_i "$i")"
    p_agent="$(agent_port_for_i "$i")"
    p_ld="$(local_dbg_port_for_i "$i")"

    for port in "$MAIN_PORT" "$FUTURE_PORT" "$STATE_SYNC_PORT" "$p_pub"; do
      if port_free "$ip" "$port"; then
        echo "  ✅ free $ip:$port"
      else
        err "node$i: CONFLICT $ip:$port"
        any_fail=1
      fi
    done

    for port in "$p_agent" "$p_ssh" "$p_ld"; do
      if port_free "127.0.0.1" "$port"; then
        echo "  ✅ free 127.0.0.1:$port"
      else
        err "node$i: CONFLICT 127.0.0.1:$port"
        any_fail=1
      fi
    done
  done

  if [ "$any_fail" -eq 1 ]; then
    err "Preflight failed. Fix IP/port conflicts and retry."
    exit 1
  fi
  log "Preflight passed: all IPs and ports are free"
}

### =========================
### RENDER FILES
### =========================
render_node_files() {
  local bootnodes="$1"
  local threshold="$2"

  log "Rendering node env/conf files into $WORKDIR"
  log "Threshold: $threshold / $N"
  log "OS_IMAGE=$OS_IMAGE  SEALING_KEY_TYPE=$SEALING_KEY_TYPE  VMM_RPC=$VMM_RPC"
  log "MPC_IMAGE_TAGS=$MPC_IMAGE_TAGS"
  log "Contract account: $MPC_CONTRACT_ACCOUNT"
  log "Node naming: node{i}.${ROOT_ACCOUNT}"

  for i in $(seq 0 $((N-1))); do
    local ip account app_name
    ip="$(ip_for_i "$i")"
    account="$(node_account_for_i "$i")"
    app_name="${MPC_NETWORK_NAME}-node${i}-testnet-tee"

    local ssh_port agent_port pub_port local_dbg_port
    ssh_port="$(ssh_port_for_i "$i")"
    agent_port="$(agent_port_for_i "$i")"
    pub_port="$(public_port_for_i "$i")"
    local_dbg_port="$(local_dbg_port_for_i "$i")"

    local env_out conf_out
    env_out="$WORKDIR/node${i}.env"
    conf_out="$WORKDIR/node${i}.conf"

    export APP_NAME="$app_name"
    export VMM_RPC
    export SEALING_KEY_TYPE
    export OS_IMAGE
    export DOCKER_COMPOSE_FILE_PATH="launcher_docker_compose.yaml"
    export USER_CONFIG_FILE_PATH="$conf_out"
    export DISK="${DISK:-500G}"

    export EXTERNAL_DSTACK_AGENT_PORT="127.0.0.1:${agent_port}"
    export EXTERNAL_SSH_PORT="127.0.0.1:${ssh_port}"
    export EXTERNAL_MPC_PUBLIC_DEBUG_PORT="${ip}:${pub_port}"
    export EXTERNAL_MPC_LOCAL_DEBUG_PORT="127.0.0.1:${local_dbg_port}"
    export EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC="${ip}:${STATE_SYNC_PORT}"
    export EXTERNAL_MPC_MAIN_PORT="${ip}:${MAIN_PORT}"
    export EXTERNAL_MPC_FUTURE_PORT="${ip}:${FUTURE_PORT}"

    export INTERNAL_MPC_PUBLIC_DEBUG_PORT="$INTERNAL_PUBLIC_DEBUG_PORT"
    export INTERNAL_MPC_LOCAL_DEBUG_PORT="$INTERNAL_LOCAL_DEBUG_PORT"
    export INTERNAL_MPC_DECENTRALIZED_STATE_SYNC="$INTERNAL_STATE_SYNC_PORT"
    export INTERNAL_MPC_MAIN_PORT="$INTERNAL_MAIN_PORT"
    export INTERNAL_MPC_FUTURE_PORT="$INTERNAL_FUTURE_PORT"

    export MPC_IMAGE_NAME="nearone/mpc-node"
    export MPC_IMAGE_TAGS="$MPC_IMAGE_TAGS"
    export MPC_REGISTRY="registry.hub.docker.com"
    export MPC_ACCOUNT_ID="$account"
    export MPC_SECRET_STORE_KEY="$(printf '%032x' "$i")"
    export MPC_CONTRACT_ID="$MPC_CONTRACT_ACCOUNT"
    export NEAR_BOOT_NODES="$bootnodes"

    envsubst <"$ENV_TPL" >"$env_out"
    envsubst <"$CONF_TPL" >"$conf_out"

    log "node$i rendered:"
    echo "  IP=$ip"
    echo "  APP_NAME=$app_name"
    echo "  ACCOUNT=$account"
    echo "  public_data=http://${ip}:${pub_port}/public_data"
    echo "  env=$env_out"
    echo "  conf=$conf_out"
  done

  log "Rendering complete"
}

### =========================
### NEAR phases
### =========================
near_phase_accounts() {
  # Ensure ROOT exists.
  if near_account_exists "$ROOT_ACCOUNT"; then
    log "account exists: $ROOT_ACCOUNT"
  else
    if [ -n "$FUNDER_ACCOUNT" ]; then
      pause_phase "NEAR: create ROOT using FUNDER_ACCOUNT (no faucet)"
      create_account_fund_myself_if_missing "$ROOT_ACCOUNT" "$ROOT_INITIAL_BALANCE" "$FUNDER_ACCOUNT"
    else
      pause_phase "NEAR: create ROOT via faucet (fallback)"
      faucet_create_with_retry "$ROOT_ACCOUNT"
    fi
  fi

  # Ensure ROOT has enough to create contract + max nodes.
  if [ -n "$FUNDER_ACCOUNT" ]; then
    pause_phase "NEAR: top-up ROOT if needed (from FUNDER_ACCOUNT)"
    topup_root_if_needed
  else
    # No funder; just warn if root is low.
    local cur target
    cur="$(near_get_balance "$ROOT_ACCOUNT")"
    target="$(required_root_balance)"
    if [ "$(float_lt "$cur" "$target")" = "1" ]; then
      warn "ROOT balance ($cur NEAR) < target ($target NEAR). You may fail creating contract/nodes."
      warn "Set FUNDER_ACCOUNT=<funded>.testnet or increase ROOT_INITIAL_BALANCE."
    fi
  fi

  maybe_stop_after_phase near_accounts
}

near_phase_nodes_and_contract() {
  if [ "$ACCOUNT_MODE" = "faucet" ]; then
    pause_phase "NEAR: faucet node accounts (legacy; may hit 429)"
    for i in $(seq 0 $((N-1))); do
      faucet_create_with_retry "$(node_account_for_i "$i")"
    done
    maybe_stop_after_phase near_nodes
    return 0
  fi

  # IMPORTANT: only ROOT can create its subaccounts (permission model)
  pause_phase "NEAR: create CONTRACT and NODE subaccounts (paid by ROOT)"
  create_account_fund_myself_if_missing "$MPC_CONTRACT_ACCOUNT" "$CONTRACT_INITIAL_BALANCE" "$ROOT_ACCOUNT"

  for i in $(seq 0 $((MAX_NODES_TO_FUND-1))); do
    create_account_fund_myself_if_missing "$(node_account_for_i "$i")" "$NODE_INITIAL_BALANCE" "$ROOT_ACCOUNT"
  done

  maybe_stop_after_phase near_nodes
}

### =========================
### DEPLOY + COLLECT
### =========================
deploy_nodes() {
  if file_nonempty "$KEYS_JSON" && [ "$FORCE_REDEPLOY" != "1" ]; then
    warn "keys.json already exists ($KEYS_JSON) -> assuming nodes already deployed. Skipping deploy (set FORCE_REDEPLOY=1 to redeploy)."
    return 0
  fi

  log "Deploying CVMs via tee_launcher/deploy-launcher.sh"
  cd "$TEE_LAUNCHER_DIR"
  [ -x "./deploy-launcher.sh" ] || { err "$TEE_LAUNCHER_DIR/deploy-launcher.sh not executable"; exit 1; }

  for i in $(seq 0 $((N-1))); do
    local ip; ip="$(ip_for_i "$i")"
    log "Deploy node$i (IP=$ip, env=$WORKDIR/node${i}.env)"
    ./deploy-launcher.sh --yes --env-file "$WORKDIR/node${i}.env" --base-path "$BASE_PATH" --python-exec python
    log "Deploy node$i completed (check output above for App ID)"
  done
}

collect_keys() {
  if file_nonempty "$KEYS_JSON" && [ "${FORCE_RECOLLECT:-0}" != "1" ]; then
    warn "keys.json already exists ($KEYS_JSON) -> skipping collection (set FORCE_RECOLLECT=1 to recollect)."
    return 0
  fi

  log "Collecting /public_data keys from each node"
  echo "[]" > "$KEYS_JSON"

  for i in $(seq 0 $((N-1))); do
    local ip pub_port url
    ip="$(ip_for_i "$i")"
    pub_port="$(public_port_for_i "$i")"
    url="http://${ip}:${pub_port}/public_data"
    log "node$i: waiting for $url"

    local ok=0
    for attempt in $(seq 1 120); do
      if curl -fsS "$url" >/dev/null 2>&1; then
        ok=1
        break
      fi
      if (( attempt % 10 == 0 )); then
        warn "node$i: still waiting for /public_data (attempt $attempt/120)"
      fi
      sleep 2
    done
    [ "$ok" -eq 1 ] || { err "Timeout waiting for $url"; exit 1; }

    local signer responder tls_pk account
    account="$(node_account_for_i "$i")"

    signer="$(curl -s "$url" | jq -r '.near_signer_public_key')"
    responder="$(curl -s "$url" | jq -r '.near_responder_public_keys[0]')"
    tls_pk="$(curl -s "$url" | jq -r '.near_p2p_public_key')"

    if [[ -z "$signer" || "$signer" == "null" ]]; then
      err "node$i: missing near_signer_public_key from $url"
      exit 1
    fi
    if [[ -z "$responder" || "$responder" == "null" ]]; then
      err "node$i: missing near_responder_public_keys[0] from $url"
      exit 1
    fi
    if [[ -z "$tls_pk" || "$tls_pk" == "null" ]]; then
      err "node$i: missing near_p2p_public_key (TLS/P2P key) from $url"
      exit 1
    fi

    tmp="$(mktemp)"
    jq --arg i "$i" --arg ip "$ip" --arg acct "$account" \
       --arg signer "$signer" --arg responder "$responder" --arg tls "$tls_pk" \
       '. + [{"i":($i|tonumber),"ip":$ip,"account":$acct,"signer_pk":$signer,"responder_pk":$responder,"tls_pk":$tls}]' \
       "$KEYS_JSON" > "$tmp"
    mv "$tmp" "$KEYS_JSON"

    log "node$i keys collected for $account"
  done

  log "Wrote $KEYS_JSON"
}


generate_init_args() {
  if file_nonempty "$INIT_ARGS_JSON" && [ "$FORCE_REINIT_ARGS" != "1" ]; then
    warn "init_args.json already exists ($INIT_ARGS_JSON) -> skipping generation (set FORCE_REINIT_ARGS=1 to regenerate)."
    return 0
  fi

  log "Generating init_args.json from $KEYS_JSON"
  [ -f "$KEYS_JSON" ] || { err "Missing keys.json at $KEYS_JSON. Run collect phase first."; exit 1; }

  local threshold="$1"
  python3 - <<PY
import json
keys=json.load(open("${KEYS_JSON}"))
threshold=int("${threshold}")
parts=[]
for k in keys:
  parts.append([k["account"], k["i"], {"sign_pk": k["tls_pk"], "url": f'https://{k["ip"]}:13001'}])
init={"parameters":{"threshold":threshold,"participants":{"next_id":len(keys),"participants":parts}}}
open("${INIT_ARGS_JSON}","w").write(json.dumps(init,indent=2))
print("Wrote", "${INIT_ARGS_JSON}")
PY

  log "init_args.json created at $INIT_ARGS_JSON"

echo
echo "================= INIT ARGS REVIEW ================="
echo "File: $INIT_ARGS_JSON"
echo "----------------------------------------------------"
jq . "$INIT_ARGS_JSON"
echo "===================================================="
echo

if [ "$NO_PAUSE" != "1" ]; then
  read -r -p "Review init_args.json above. Press ENTER to continue, Ctrl+C to abort..." _
  echo
else
  log "NO_PAUSE=1 -> skipping init_args.json confirmation pause"
fi
}

### =========================
### Contract + votes phases (unchanged)
### =========================
build_contract() {
  log "Building MPC contract"
  cargo near build non-reproducible-wasm --features abi --manifest-path crates/contract/Cargo.toml --locked
  export MPC_CONTRACT_PATH="$(pwd)/target/near/mpc_contract/mpc_contract.wasm"
  [ -f "$MPC_CONTRACT_PATH" ] || { err "Contract wasm not found at $MPC_CONTRACT_PATH"; exit 1; }
  log "MPC_CONTRACT_PATH=$MPC_CONTRACT_PATH"
}

deploy_contract() {
  log "Deploying MPC contract to $MPC_CONTRACT_ACCOUNT"
  NEAR_CLI_DISABLE_SPINNER=1 near contract deploy "$MPC_CONTRACT_ACCOUNT" use-file "$MPC_CONTRACT_PATH" \
    without-init-call network-config testnet sign-with-keychain send
}

add_node_keys_from_keysjson() {
  log "Adding node keys to NEAR accounts using $KEYS_JSON"
  [ -f "$KEYS_JSON" ] || { err "Missing keys.json at $KEYS_JSON. Run collect phase first."; exit 1; }

  jq -c '.[]' "$KEYS_JSON" | while read -r row; do
    local acct signer responder
    acct="$(echo "$row" | jq -r .account)"
    signer="$(echo "$row" | jq -r .signer_pk)"
    responder="$(echo "$row" | jq -r .responder_pk)"

    log "$acct: add signer key"
    NEAR_CLI_DISABLE_SPINNER=1 near account add-key "$acct" grant-full-access \
      use-manually-provided-public-key "$signer" \
      network-config testnet sign-with-keychain send

    near_sleep "add signer key for $acct"
    log "$acct: add responder key"
    NEAR_CLI_DISABLE_SPINNER=1 near account add-key "$acct" grant-full-access \
      use-manually-provided-public-key "$responder" \
      network-config testnet sign-with-keychain send
    near_sleep "add responder key for $acct"
  done
}

init_contract() {
  log "Initializing contract using $INIT_ARGS_JSON"
  [ -f "$INIT_ARGS_JSON" ] || { err "Missing init_args.json at $INIT_ARGS_JSON. Run init_args phase first."; exit 1; }

  NEAR_CLI_DISABLE_SPINNER=1 near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" init \
    file-args "$INIT_ARGS_JSON" prepaid-gas '300.0 Tgas' \
    attached-deposit '0 NEAR' sign-as "$MPC_CONTRACT_ACCOUNT" \
    network-config testnet sign-with-keychain send
}

extract_code_hash() {
  local digest
  digest="$(grep -E "DEFAULT_IMAGE_DIGEST=sha256:" "$COMPOSE_YAML" | head -n1 | sed -E 's/.*sha256:([0-9a-f]{64}).*/\1/')"
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    err "Could not extract DEFAULT_IMAGE_DIGEST from $COMPOSE_YAML"
    exit 1
  fi
  echo "$digest"
}

vote_code_hash_threshold() {
  local threshold="$1"
  local code_hash="$2"
  log "Voting code hash with threshold=$threshold (CODE_HASH=$code_hash)"
  for i in $(seq 0 $((threshold-1))); do
    local acct
    acct="$(node_account_for_i "$i")"
    log "vote_code_hash as $acct"
    NEAR_CLI_DISABLE_SPINNER=1 near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" vote_code_hash \
      json-args "{\"code_hash\": \"$code_hash\"}" prepaid-gas '100.0 Tgas' \
      attached-deposit '0 NEAR' sign-as "$acct" \
      network-config testnet sign-with-keychain send
    near_sleep "vote_code_hash by $acct"
  done
}

vote_add_domain_threshold() {
  local threshold="$1"
  log "Voting add domain with threshold=$threshold (file=$ADD_DOMAIN_JSON)"
  for i in $(seq 0 $((threshold-1))); do
    local acct
    acct="$(node_account_for_i "$i")"
    log "vote_add_domains as $acct"
    NEAR_CLI_DISABLE_SPINNER=1 near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" vote_add_domains \
      file-args "$ADD_DOMAIN_JSON" prepaid-gas '300.0 Tgas' \
      attached-deposit '0 NEAR' sign-as "$acct" \
      network-config testnet sign-with-keychain send
  done
}

print_summary() {
  local threshold="$1"
  local code_hash="$2"
  echo
  echo "============================================================"
  log "Summary"
  echo "------------------------------------------------------------"
  echo " Network name        : $MPC_NETWORK_NAME"
  echo " ROOT_ACCOUNT        : $ROOT_ACCOUNT"
  echo " CONTRACT_ACCOUNT    : $MPC_CONTRACT_ACCOUNT"
  echo " Threshold           : $threshold / $N"
  echo " Workdir             : $WORKDIR"
  echo " FUNDER_ACCOUNT      : ${FUNDER_ACCOUNT:-<none>}"
  echo " ROOT_INITIAL_BAL    : $ROOT_INITIAL_BALANCE (target supports 10 nodes)"
  echo " CONTRACT_BAL        : $CONTRACT_INITIAL_BALANCE"
  echo " NODE_BAL            : $NODE_INITIAL_BALANCE"
  echo " MAX_NODES_TO_FUND   : $MAX_NODES_TO_FUND"
  echo " MPC_IMAGE_TAGS      : $MPC_IMAGE_TAGS"
  echo " CODE_HASH           : $code_hash"
  echo "============================================================"
}

### =========================
### MAIN
### =========================
echo "============================================================"
echo " MPC Testnet TEE Scale Deployment"
echo "------------------------------------------------------------"
echo " Base network name : $MPC_NETWORK_BASE_NAME"
echo " Random suffix     : $RAND_SUFFIX"
echo " FINAL network     : $MPC_NETWORK_NAME"
echo " Nodes             : $N"
echo " WORKDIR           : $WORKDIR"
echo " FUNDER_ACCOUNT    : ${FUNDER_ACCOUNT:-<none>}"
echo " ROOT_INITIAL_BAL  : $ROOT_INITIAL_BALANCE"
echo " CONTRACT_BAL      : $CONTRACT_INITIAL_BALANCE"
echo " NODE_BAL          : $NODE_INITIAL_BALANCE"
echo " MAX_NODES_TO_FUND : $MAX_NODES_TO_FUND"
echo " START_FROM_PHASE  : $START_FROM_PHASE"
echo " STOP_AFTER_PHASE  : ${STOP_AFTER_PHASE:-<none>}"
echo " RESUME            : $RESUME"
echo "============================================================"
echo

main() {
  local threshold bootnodes code_hash
  threshold="$(ceil_2n_3 "$N")"

  local auto_start
  auto_start="$(compute_auto_start_phase)"
  if [ "$START_FROM_PHASE" = "auto" ]; then
    START_FROM_PHASE="$auto_start"
    log "AUTO start phase selected: $START_FROM_PHASE (based on artifacts)"
  else
    log "Start phase requested: $START_FROM_PHASE"
  fi

  log "Network: $MPC_NETWORK_NAME"
  log "N=$N threshold=$threshold"
  log "Repo: $REPO_ROOT"
  log "Workdir: $WORKDIR"
  log "ROOT_ACCOUNT: $ROOT_ACCOUNT"
  log "CONTRACT_ACCOUNT: $MPC_CONTRACT_ACCOUNT"

  if should_run_from_start preflight; then
    pause_phase "Preflight (no side effects)"
    preflight
    maybe_stop_after_phase preflight
  fi

  if should_run_from_start render; then
    pause_phase "Fetch bootnodes (dedup) + render node env/conf files"
    bootnodes="$(fetch_bootnodes)"
    log "Fetched bootnodes length: ${#bootnodes}"
    render_node_files "$bootnodes" "$threshold"
    maybe_stop_after_phase render
  fi

  if should_run_from_start near_accounts; then
    near_phase_accounts
  fi

  if should_run_from_start near_nodes; then
    near_phase_nodes_and_contract
  fi

  if should_run_from_start near_contract; then
    pause_phase "NEAR: build + deploy MPC contract"
    build_contract
    deploy_contract
    maybe_stop_after_phase near_contract
  fi

  if should_run_from_start deploy; then
    pause_phase "Deploy CVMs (dstack)"
    deploy_nodes
    maybe_stop_after_phase deploy
  fi

  if should_run_from_start collect; then
    pause_phase "Collect node keys from /public_data"
    collect_keys
    maybe_stop_after_phase collect
  fi

  if should_run_from_start init_args; then
    pause_phase "Generate init_args.json"
    generate_init_args "$threshold"
    maybe_stop_after_phase init_args
  fi

  if should_run_from_start near_keys; then
    pause_phase "NEAR: add signer+responder keys to node accounts"
    add_node_keys_from_keysjson
    maybe_stop_after_phase near_keys
  fi

  if should_run_from_start near_init; then
    pause_phase "NEAR: init contract"
    init_contract
    maybe_stop_after_phase near_init
  fi

 if should_run_from_start near_vote_hash; then
  pause_phase "NEAR: vote code hash"
  code_hash="$(extract_code_hash)"
  log "CODE_HASH (no prefix): $code_hash"
  vote_code_hash_threshold "$threshold" "$code_hash"
  maybe_stop_after_phase near_vote_hash
 fi

 if should_run_from_start near_vote_domain; then
  pause_phase "NEAR: vote add domain"
  vote_add_domain_threshold "$threshold"
  maybe_stop_after_phase near_vote_domain
 fi


  code_hash="$(extract_code_hash || true)"
  print_summary "$threshold" "${code_hash:-<unknown>}"
  log "✅ Done"
}

main "$@"
