#!/usr/bin/env bash
# =============================================================================
# MPC Localnet TEE — backup-cli migration test
# =============================================================================
#
# Drives a full node-migration cycle on a 2-node localnet TEE cluster:
#
#   prepare       -> bring up A0 + A1 via deploy-tee-cluster.sh (clean deploy)
#   deploy-target -> bring up B0 (third CVM, sharing A0's NEAR account)
#   forward       -> register backup-cli + GET keyshares from A0 +
#                    start_node_migration + PUT keyshares to B0 + verify
#   back          -> stop & restart A0's CVM, then GET from B0 + PUT to A0
#                    (this is the empirical reproduction attempt for #2121)
#   both          -> forward + back
#   status        -> dump migration_info, get_tee_accounts, state
#   cleanup       -> remove B0's CVM and the local backup tmp dir
#
# Caveat: localnet TDX provides REAL Dstack attestation, so this exercises
# the real-attestation path the Rust E2E harness mocks. It does NOT
# naturally produce a stale on-chain attestation (TDX collateral TTL is
# ~7 days). A happy back-migration result here pushes the bug specifically
# toward "stale collateral", not "any real attestation".
#
# Prereqs:
#   - dstack VMM running at $VMM_RPC
#   - $BASE_PATH points at the dstack base dir (contains vmm/src/vmm-cli.py)
#   - 51.68.219.{1,2,3} configured on the host (alice profile)
#   - `near` CLI in PATH, mpc-localnet keychain configured
#   - `jq`, `envsubst`, `python3`, `curl` available
#
# Usage:
#   source localnet/tee/scripts/rust-launcher/set-localnet-env.sh
#   export MPC_NETWORK_BASE_NAME=mpc-local   # match deploy-tee-cluster.sh
#   bash localnet/tee/scripts/rust-launcher/test-migration.sh both
#
# =============================================================================
set -euo pipefail
export NEAR_CLI_DISABLE_SPINNER=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy-tee-cluster.sh"
LAUNCHER_DIR="$REPO_ROOT/deployment/cvm-deployment"
ENV_TPL="$REPO_ROOT/localnet/tee/scripts/node.env.tpl"
CONF_TPL="$REPO_ROOT/localnet/tee/scripts/rust-launcher/node.conf.localnet.toml.tpl"

# ---------- env defaults (kept in sync with deploy-tee-cluster.sh) ----------
NEAR_NETWORK_CONFIG="${NEAR_NETWORK_CONFIG:-mpc-localnet}"
N="${N:-2}"
ACCOUNT_SUFFIX="${ACCOUNT_SUFFIX:-.test.near}"
MPC_NETWORK_BASE_NAME="${MPC_NETWORK_BASE_NAME:?Must set MPC_NETWORK_BASE_NAME (e.g. mpc-local)}"
MPC_NETWORK_NAME="${REUSE_NETWORK_NAME:-${MPC_NETWORK_BASE_NAME}}"
ROOT_ACCOUNT="${MPC_NETWORK_NAME}${ACCOUNT_SUFFIX}"
MPC_CONTRACT_ACCOUNT="${MPC_CONTRACT_ACCOUNT:-mpc.${ROOT_ACCOUNT}}"
VMM_RPC="${VMM_RPC:-http://127.0.0.1:10000}"
BASE_PATH="${BASE_PATH:?Must set BASE_PATH}"
CLI="python3 $BASE_PATH/vmm/src/vmm-cli.py --url $VMM_RPC"
OS_IMAGE="${OS_IMAGE:-dstack-dev-0.5.8}"
SEALING_KEY_TYPE="${SEALING_KEY_TYPE:-SGX}"
DISK="${DISK:-500G}"

# Manifest digests (from set-localnet-env.sh or operator override)
: "${MPC_MANIFEST_DIGEST:?Must export MPC_MANIFEST_DIGEST (sha256:...)}"
: "${LAUNCHER_MANIFEST_DIGEST:?Must export LAUNCHER_MANIFEST_DIGEST (sha256:...)}"

# Workdir matches deploy-tee-cluster.sh — we read its rendered node0.env etc.
WORKDIR="/tmp/${USER}/mpc_testnet_scale/${MPC_NETWORK_NAME}"
mkdir -p "$WORKDIR"

# Host profile / IPs / ports — keep aligned with deploy-tee-cluster.sh defaults
HOST_PROFILE="${HOST_PROFILE:-alice}"
case "$HOST_PROFILE" in
  alice) IP_PREFIX="51.68.219."; IP_START_OCTET=1 ;;
  bob)   IP_PREFIX="5.196.36.";  IP_START_OCTET=113 ;;
  *) echo "Unknown HOST_PROFILE=$HOST_PROFILE"; exit 1 ;;
esac

MAIN_PORT="${MAIN_PORT:-80}"                   # P2P/TLS — `port_override=80` makes the node bind here
PUBLIC_DATA_BASE="${PUBLIC_DATA_BASE:-18082}"  # public_data is fixed at 18082 per port handler
MIGRATION_PORT="${MIGRATION_PORT:-8079}"       # migration HTTP — uniform across CVMs, per-IP isolation
STATE_SYNC_PORT="${STATE_SYNC_PORT:-24567}"
SSH_BASE="${SSH_BASE:-22220}"
AGENT_BASE="${AGENT_BASE:-18090}"
LOCAL_DEBUG_BASE="${LOCAL_DEBUG_BASE:-3030}"  # uses random offset per node

# Migration target params (B0)
B_INDEX="${B_INDEX:-2}"
B_SOURCE_INDEX="${B_SOURCE_INDEX:-0}"   # which node B0 is migrating from
# Distinct secret_store_key from A0 ("00…00") and A1 ("00…01")
B_SECRET_STORE_KEY="${B_SECRET_STORE_KEY:-$(printf '%032x' 99)}"

# Backup-cli / migration test config
BACKUP_HOME_DIR="${BACKUP_HOME_DIR:-/tmp/${USER}/mpc-migration-backup}"
BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-0000000000000000000000000000000000000000000000000000000000000000}"
BACKUP_CLI="${BACKUP_CLI:-$REPO_ROOT/target/release/backup-cli}"

# ---------- logging ----------
log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }
pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; }
fatal(){ err "$*"; exit 1; }

# ---------- helpers ----------
node_account_for_i() {
  # The migration target B0 (index B_INDEX) shares its NEAR account with the
  # source node it migrates from (B_SOURCE_INDEX). All other indices map
  # directly. This is what makes migration on-chain a "TLS-key swap" rather
  # than a participant set change.
  if [ "$1" = "$B_INDEX" ]; then
    echo "node${B_SOURCE_INDEX}.${ROOT_ACCOUNT}"
  else
    echo "node$1.${ROOT_ACCOUNT}"
  fi
}
ip_for_i()           { echo "${IP_PREFIX}$((IP_START_OCTET + $1))"; }
migration_port_for_i() { echo "$MIGRATION_PORT"; }  # same on every CVM; per-IP isolation
agent_port_for_i()   { echo $((AGENT_BASE + $1)); }
ssh_port_for_i()     { echo $((SSH_BASE + $1)); }
local_dbg_port_for_i() { echo $((LOCAL_DEBUG_BASE + $1 + 100)); }  # offset to dodge neard's 3030
public_port_for_i()  { echo "$PUBLIC_DATA_BASE"; }
b_app_name()         { echo "${MPC_NETWORK_NAME}-node${B_INDEX}-migration-tee"; }

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
# Extract the JSON return value of a near call. Two variants because read-only
# and as-transaction output differs (mirrors test-verify-and-upgrade.sh).
extract_json_tx() {
  sed -n '/^Function execution return value/,/^$/{ /^Function/d; /^$/d; p }' \
    | sed '/^Here is your console/,$d' \
    | sed 's/^│[[:space:]]*//' \
    | sed '/^$/d'
}
extract_json_ro() {
  sed -n '/^Function execution return value/,/^Here is your console/{
    /^Function/d; /^Here is your console/d; p
  }'
}

# ---------- backup-cli plumbing ----------
ensure_backup_cli() {
  if [ ! -x "$BACKUP_CLI" ]; then
    log "Building backup-cli (release)"
    (cd "$REPO_ROOT" && cargo build --release -p backup-cli --locked)
  fi
  [ -x "$BACKUP_CLI" ] || fatal "backup-cli not built at $BACKUP_CLI"
}

ensure_backup_keys() {
  if [ -f "$BACKUP_HOME_DIR/secrets.json" ]; then
    log "Reusing backup-cli keys at $BACKUP_HOME_DIR"
    return 0
  fi
  mkdir -p "$BACKUP_HOME_DIR"
  log "Generating backup-cli keys at $BACKUP_HOME_DIR"
  "$BACKUP_CLI" --home-dir "$BACKUP_HOME_DIR" generate-keys
}

# Extract the public_key the backup-cli would register with, by parsing the
# `register` subcommand's near CLI output.
backup_cli_pubkey() {
  "$BACKUP_CLI" --home-dir "$BACKUP_HOME_DIR" register \
    --mpc-contract-account-id "$MPC_CONTRACT_ACCOUNT" \
    --near-network "$NEAR_NETWORK_CONFIG" \
    --signer-account-id "$(node_account_for_i "$B_SOURCE_INDEX")" 2>&1 \
    | grep -oE 'ed25519:[1-9A-HJ-NP-Za-km-z]+' | head -1
}

# Register the backup-cli's public key on the contract under the source account.
# Idempotent — re-running just refreshes the entry. Waits for the source node's
# indexer to catch up to the new registration (else GET keyshares races the
# indexer and the node closes the TLS connection before authorizing).
register_backup_service() {
  ensure_backup_cli
  ensure_backup_keys
  local pk acct
  pk="$(backup_cli_pubkey)"
  acct="$(node_account_for_i "$B_SOURCE_INDEX")"
  [ -n "$pk" ] || fatal "could not derive backup-cli public key"
  log "Registering backup-cli pk=$pk for account=$acct"
  near_call_tx register_backup_service \
    "{\"backup_service_info\":{\"public_key\":\"$pk\"}}" "$acct" \
    | tail -5

  wait_for_source_indexer_backup_service "$B_SOURCE_INDEX" "$pk"
}

# Poll the source node's /debug/migrations until backup_service.public_key
# matches `expected_pk`. The source MPC node uses its own indexer view to
# authorize backup-cli, so we must wait for the indexer to ingest the
# register_backup_service tx before issuing GET keyshares.
wait_for_source_indexer_backup_service() {
  local source_idx="$1" expected_pk="$2"
  local ip; ip="$(ip_for_i "$source_idx")"
  local acct; acct="$(node_account_for_i "$source_idx")"
  log "Waiting for node$source_idx indexer to see backup_service=$expected_pk"
  for attempt in $(seq 1 60); do
    local actual
    actual="$(curl -sf "http://${ip}:18082/debug/migrations" 2>/dev/null \
              | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)[1].get('$acct', [None, None])[0] or {}
    print(d.get('public_key',''))
except Exception:
    print('')
" 2>/dev/null)"
    if [ "$actual" = "$expected_pk" ]; then
      pass "Source node indexer caught up"
      return 0
    fi
    sleep 2
  done
  fatal "source node indexer did not register backup_service within 120s (last seen: $actual)"
}

# Poll the target node's /debug/migrations until destination_node_info.tls_public_key
# matches expected — the target's indexer must see the start_node_migration tx
# before backup-cli's PUT lands (otherwise mid-PUT the active_migration flip
# trips the migration web server's cancellation token and tears down TLS).
wait_for_target_indexer_destination() {
  local source_idx="$1" target_tls="$2"
  local ip; ip="$(ip_for_i "$source_idx")"  # debug endpoint is on the SOURCE (it owns the migration)
  local acct; acct="$(node_account_for_i "$source_idx")"
  log "Waiting for source-node indexer to see destination tls=$target_tls"
  for attempt in $(seq 1 60); do
    local actual
    actual="$(curl -sf "http://${ip}:18082/debug/migrations" 2>/dev/null \
              | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)[1].get('$acct', [None, None])[1] or {}
    info = d.get('destination_node_info', {})
    print(info.get('tls_public_key',''))
except Exception:
    print('')
" 2>/dev/null)"
    if [ "$actual" = "$target_tls" ]; then
      pass "Source node indexer saw destination"
      return 0
    fi
    sleep 2
  done
  fatal "source node indexer did not register destination within 120s (last seen: $actual)"
}

# Save current contract state into BACKUP_HOME_DIR/contract_state.json
# (backup-cli reads this to know the current epoch/keyset before GET/PUT).
save_contract_state() {
  local out="$BACKUP_HOME_DIR/contract_state.json"
  log "Saving contract state to $out"
  # near CLI emits ANSI/formatting on stderr and the raw JSON return value
  # on stdout — redirect stderr away so the file is clean JSON for backup-cli.
  near contract call-function as-read-only "$MPC_CONTRACT_ACCOUNT" state \
    json-args {} network-config "$NEAR_NETWORK_CONFIG" now > "$out" 2>/dev/null
  [ -s "$out" ] || fatal "contract_state.json is empty"
  # Sanity-check parseable JSON
  python3 -c "import json,sys; json.load(open('$out'))" 2>/dev/null \
    || fatal "contract_state.json is not valid JSON; head: $(head -1 "$out")"
}

# Fetch tls_public_key + near_signer_public_key for a given index from its
# CVM's /public_data endpoint.
fetch_node_keys() {
  local i="$1" out="$2"
  local ip url
  ip="$(ip_for_i "$i")"
  url="http://${ip}:$(public_port_for_i "$i")/public_data"
  log "Fetching keys for node$i from $url"
  for attempt in $(seq 1 120); do
    if curl -fsS "$url" > "$out" 2>/dev/null; then
      [ -s "$out" ] && return 0
    fi
    sleep 2
  done
  fatal "node$i: /public_data never responded at $url"
}

# ---------- migration target deployment ----------
render_target_files() {
  local target_idx="$B_INDEX"
  local source_idx="$B_SOURCE_INDEX"
  local ip; ip="$(ip_for_i "$target_idx")"
  local account; account="$(node_account_for_i "$source_idx")"  # SAME as A0
  local app_name; app_name="$(b_app_name)"
  local migration_port; migration_port="$(migration_port_for_i "$target_idx")"  # always 8079
  local agent_port; agent_port="$(agent_port_for_i "$target_idx")"
  local ssh_port; ssh_port="$(ssh_port_for_i "$target_idx")"
  local pub_port; pub_port="$(public_port_for_i "$target_idx")"
  local local_dbg_port; local_dbg_port="$(local_dbg_port_for_i "$target_idx")"

  export APP_NAME="$app_name"
  export VMM_RPC SEALING_KEY_TYPE OS_IMAGE DISK
  export LAUNCHER_MANIFEST_DIGEST MPC_MANIFEST_DIGEST

  export EXTERNAL_DSTACK_AGENT_PORT="127.0.0.1:${agent_port}"
  export EXTERNAL_SSH_PORT="127.0.0.1:${ssh_port}"
  export EXTERNAL_MPC_PUBLIC_DEBUG_PORT="${ip}:${pub_port}"
  export EXTERNAL_MPC_LOCAL_DEBUG_PORT="127.0.0.1:${local_dbg_port}"
  export EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC="${ip}:${STATE_SYNC_PORT}"
  export EXTERNAL_MPC_MAIN_PORT="${ip}:${MAIN_PORT}"               # P2P/TLS (port_override=80)
  export EXTERNAL_MPC_MIGRATION_PORT="${ip}:${migration_port}"     # migration HTTP (8079)

  export INTERNAL_MPC_PUBLIC_DEBUG_PORT=8080
  export INTERNAL_MPC_LOCAL_DEBUG_PORT=3030
  export INTERNAL_MPC_DECENTRALIZED_STATE_SYNC=24567
  export INTERNAL_MPC_MAIN_PORT=80
  export INTERNAL_MPC_MIGRATION_PORT="${migration_port}"           # 8079, container's migration_web_ui

  export MPC_ENV="$NEAR_NETWORK_CONFIG"
  export MPC_IMAGE="nearone/mpc-node"
  export MPC_ACCOUNT_ID="$account"             # KEY OVERRIDE: same as A0
  export MPC_SECRET_STORE_KEY="$B_SECRET_STORE_KEY"  # distinct from A0
  export MPC_CONTRACT_ID="$MPC_CONTRACT_ACCOUNT"

  # Localnet: route CVM outbound to host neard via the QEMU slirp gateway.
  # Forward MAIN(80) for P2P/TLS, 8080 for /public_data, 24566 for neard, 8079 for migration.
  export PORTS="${MAIN_PORT}:${INTERNAL_MPC_MAIN_PORT},8080:8080,24566:24566,${migration_port}:${migration_port}"
  export NEAR_BOOT_NODES="ed25519:BGa4WiBj43Mr66f9Ehf6swKtR6wZmWuwCsV3s4PSR3nx@10.0.2.2:24566"

  # PORTS_TOML transformation (same shape as deploy-tee-cluster.sh).
  local PORTS_TOML="" pair host_port container_port
  IFS=',' read -ra pairs <<< "$PORTS"
  for pair in "${pairs[@]}"; do
    host_port="${pair%%:*}"
    container_port="${pair##*:}"
    PORTS_TOML+="    { host =${host_port}, container =${container_port} },
"
  done
  export PORTS_TOML

  local env_out="$WORKDIR/node${target_idx}.env"
  local conf_out="$WORKDIR/node${target_idx}.toml"
  export USER_CONFIG_FILE_PATH="$conf_out"

  log "Rendering target env -> $env_out"
  envsubst <"$ENV_TPL" >"$env_out"
  log "Rendering target conf -> $conf_out"
  envsubst <"$CONF_TPL" >"$conf_out"
}

deploy_target() {
  # Idempotency: skip if a VM with the migration app name is already running.
  local app; app="$(b_app_name)"
  if $CLI lsvm 2>/dev/null | grep -q "$app.*running"; then
    log "Migration target VM '$app' already running — skipping deploy"
    return 0
  fi

  render_target_files

  local ip; ip="$(ip_for_i "$B_INDEX")"
  log "Deploying migration target B0 (app=$app, ip=$ip, idx=$B_INDEX, account=$(node_account_for_i "$B_SOURCE_INDEX"))"

  (cd "$LAUNCHER_DIR" \
    && ./deploy-launcher.sh --yes \
        --env-file "$WORKDIR/node${B_INDEX}.env" \
        --base-path "$BASE_PATH" \
        --python-exec python)

  # Wait for /public_data to respond — confirms launcher + MPC node are up.
  local pub_port; pub_port="$(public_port_for_i "$B_INDEX")"
  local url="http://${ip}:${pub_port}/public_data"
  log "Waiting for $url ..."
  for attempt in $(seq 1 180); do
    curl -fsS "$url" >/dev/null 2>&1 && { pass "Migration target online"; return 0; }
    sleep 2
  done
  fatal "Migration target did not come online within 6 min"
}

# Add B0's near_signer_public_key as a function-call access key on A0's account
# so B0 can call node-facing methods (conclude_node_migration etc).
add_target_signer_key() {
  local keys_json="$WORKDIR/node${B_INDEX}.keys.json"
  fetch_node_keys "$B_INDEX" "$keys_json"
  local signer responder acct
  signer="$(jq -r '.near_signer_public_key' "$keys_json")"
  responder="$(jq -r '.near_responder_public_keys[0]' "$keys_json")"
  acct="$(node_account_for_i "$B_SOURCE_INDEX")"
  [ -n "$signer" ] && [ "$signer" != "null" ] || fatal "missing near_signer_public_key for B0"
  log "Adding B0's signer key ($signer) to $acct as restricted FC-access key"

  local node_methods="respond,respond_ckd,respond_verify_foreign_tx,vote_pk,start_keygen_instance,vote_reshared,register_foreign_chain_config,start_reshare_instance,vote_abort_key_event_instance,verify_tee,submit_participant_info,conclude_node_migration"

  set +e
  near account add-key "$acct" grant-function-call-access \
    --allowance unlimited \
    --contract-account-id "$MPC_CONTRACT_ACCOUNT" \
    --function-names "$node_methods" \
    use-manually-provided-public-key "$signer" \
    network-config "$NEAR_NETWORK_CONFIG" sign-with-keychain send 2>&1 | tail -3
  local rc=$?
  set -e

  if [ -n "$responder" ] && [ "$responder" != "null" ]; then
    log "Adding B0's responder key ($responder) to $acct"
    set +e
    near account add-key "$acct" grant-function-call-access \
      --allowance unlimited \
      --contract-account-id "$MPC_CONTRACT_ACCOUNT" \
      --function-names "$node_methods" \
      use-manually-provided-public-key "$responder" \
      network-config "$NEAR_NETWORK_CONFIG" sign-with-keychain send 2>&1 | tail -3
    set -e
  fi

  if [ $rc -ne 0 ]; then
    warn "add-key returned non-zero — may just mean the key already exists"
  fi

  # Sanity: wait until contract sees B0's attestation
  log "Waiting for contract to register B0's TEE attestation..."
  for attempt in $(seq 1 60); do
    local tee_out tee_json count
    tee_out="$(near_call_tx get_tee_accounts '{}' "$acct" 2>&1)"
    tee_json="$(echo "$tee_out" | extract_json_tx)"
    count="$(echo "$tee_json" | jq "[.[] | select(.account_id==\"$acct\")] | length" 2>/dev/null || echo 0)"
    if [ "${count:-0}" -ge 2 ]; then
      pass "Contract shows 2 TEE attestations for $acct (A0 + B0)"
      return 0
    fi
    sleep 5
  done
  fatal "Contract never registered B0's attestation under $acct"
}

# ---------- migration flow ----------

# GET keyshares from `source_idx` -> $BACKUP_HOME_DIR/permanent_keys/
do_get_keyshares() {
  local source_idx="$1"
  local ip mport tls_key keys_json
  ip="$(ip_for_i "$source_idx")"
  mport="$(migration_port_for_i "$source_idx")"
  keys_json="$WORKDIR/node${source_idx}.keys.json"
  fetch_node_keys "$source_idx" "$keys_json"
  tls_key="$(jq -r '.near_p2p_public_key' "$keys_json")"

  save_contract_state

  log "GET keyshares from node$source_idx at ${ip}:${mport} (tls=$tls_key)"
  "$BACKUP_CLI" --home-dir "$BACKUP_HOME_DIR" get-keyshares \
    --mpc-node-address "${ip}:${mport}" \
    --mpc-node-p2p-key "$tls_key" \
    --backup-encryption-key-hex "$BACKUP_ENCRYPTION_KEY"
  pass "GET keyshares completed (saved under $BACKUP_HOME_DIR/permanent_keys/)"
}

# Tell contract to migrate from source -> target. Source account is the
# operator's; target params come from the target's /public_data.
#
# The URL we publish here becomes the contract participant URL after
# conclude_node_migration. With `port_override = 80` in the toml, the MPC
# node ignores the URL port and binds P2P on 80 regardless — we publish 80
# explicitly for clarity and to match init_args.
do_start_node_migration() {
  local source_idx="$1" target_idx="$2"
  local source_acct ip keys_json signer_pk tls_pk
  source_acct="$(node_account_for_i "$source_idx")"
  ip="$(ip_for_i "$target_idx")"
  keys_json="$WORKDIR/node${target_idx}.keys.json"
  fetch_node_keys "$target_idx" "$keys_json"
  signer_pk="$(jq -r '.near_signer_public_key' "$keys_json")"
  tls_pk="$(jq -r '.near_p2p_public_key' "$keys_json")"

  local url="https://${ip}:${MAIN_PORT}"
  log "start_node_migration: source=$source_acct -> target_tls=$tls_pk url=$url"

  local args
  args="$(jq -nc \
    --arg pk "$signer_pk" --arg url "$url" --arg tls "$tls_pk" \
    '{destination_node_info: {signer_account_pk:$pk, destination_node_info: {url:$url, tls_public_key:$tls}}}')"
  near_call_tx start_node_migration "$args" "$source_acct" | tail -5

  # Wait for the source node's indexer to see the active_migration entry —
  # backup-cli's PUT relies on it (else mid-PUT the destination_node_info
  # flip trips the migration server's cancellation token).
  wait_for_target_indexer_destination "$source_idx" "$tls_pk"
}

# PUT keyshares to target_idx via the backup-cli.
do_put_keyshares() {
  local target_idx="$1"
  local ip mport keys_json tls_key
  ip="$(ip_for_i "$target_idx")"
  mport="$(migration_port_for_i "$target_idx")"
  keys_json="$WORKDIR/node${target_idx}.keys.json"
  fetch_node_keys "$target_idx" "$keys_json"
  tls_key="$(jq -r '.near_p2p_public_key' "$keys_json")"

  save_contract_state

  log "PUT keyshares to node$target_idx at ${ip}:${mport} (tls=$tls_key)"
  "$BACKUP_CLI" --home-dir "$BACKUP_HOME_DIR" put-keyshares \
    --mpc-node-address "${ip}:${mport}" \
    --mpc-node-p2p-key "$tls_key" \
    --backup-encryption-key-hex "$BACKUP_ENCRYPTION_KEY"
  pass "PUT keyshares completed"
}

# Poll until contract.migration_info[source] has no destination AND
# contract.state shows target's tls_public_key as the participant for source's account.
wait_for_migration_completion() {
  local source_idx="$1" target_idx="$2"
  local source_acct target_tls
  source_acct="$(node_account_for_i "$source_idx")"
  target_tls="$(jq -r '.near_p2p_public_key' "$WORKDIR/node${target_idx}.keys.json")"

  log "Waiting for contract to finalize $source_acct -> tls=$target_tls (up to 120s)"
  for attempt in $(seq 1 60); do
    local mi state mi_json state_json
    mi="$(near_call_ro migration_info '{}')"
    mi_json="$(echo "$mi" | extract_json_ro)"
    local dest
    dest="$(echo "$mi_json" | jq -r --arg a "$source_acct" '.[$a][1]' 2>/dev/null || echo "null")"

    state="$(near_call_ro state '{}')"
    state_json="$(echo "$state" | extract_json_ro)"
    local found_tls
    found_tls="$(echo "$state_json" | jq -r --arg a "$source_acct" '
      .Running.parameters.participants.participants[]
      | select(.[0]==$a) | .[2].tls_public_key' 2>/dev/null | head -1)"

    if [ "$dest" = "null" ] && [ "$found_tls" = "$target_tls" ]; then
      pass "Migration finalized: migration_info clear and participant TLS == target"
      return 0
    fi
    sleep 2
  done

  err "Migration did NOT finalize. Last state:"
  echo "  migration_info[$source_acct].destination = $dest"
  echo "  participants[$source_acct].tls_public_key = ${found_tls:-<unknown>}"
  echo "  expected target_tls = $target_tls"
  return 1
}

verify_signing() {
  log "Verifying signature generation works"
  local sign_ok=0
  for attempt in 1 2 3 4; do
    local out
    out="$(near contract call-function as-transaction "$MPC_CONTRACT_ACCOUNT" sign \
      file-args "$REPO_ROOT/docs/localnet/args/sign_ecdsa.json" \
      prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
      sign-as "$(node_account_for_i 0)" network-config "$NEAR_NETWORK_CONFIG" \
      sign-with-keychain send 2>&1)"
    if echo "$out" | grep -q '"big_r"'; then
      pass "ECDSA signature succeeded"
      sign_ok=1
      break
    fi
    [ $attempt -lt 4 ] && { warn "sign attempt $attempt failed, retry in 30s"; sleep 30; }
  done
  [ $sign_ok -eq 1 ] || fatal "ECDSA signing failed after 4 attempts"
}

# Find the VM id for node `i`. Matches by app name pattern used at deploy.
vm_id_for() {
  local i="$1" app
  if [ "$i" = "$B_INDEX" ]; then
    app="$(b_app_name)"
  else
    app="${MPC_NETWORK_NAME}-node${i}-testnet-tee"
  fi
  $CLI lsvm 2>/dev/null | grep "$app" | awk '{print $2}' | tail -1
}

# Stop + start A0's CVM (state preserved). This is what makes back-migration
# meaningful: A0's keyshares are still on disk on restart — the exact
# precondition for the P1 early-return.
restart_source_node() {
  local i="$B_SOURCE_INDEX"
  local vm; vm="$(vm_id_for "$i")"
  [ -n "$vm" ] || fatal "could not find VM for node$i"
  log "Stopping A0 (node$i, vm=$vm) ..."
  $CLI stop -f "$vm" 2>/dev/null || true
  sleep 5
  log "Starting A0 (node$i, vm=$vm) ..."
  $CLI start "$vm" 2>/dev/null
  local ip; ip="$(ip_for_i "$i")"
  local url="http://${ip}:$(public_port_for_i "$i")/public_data"
  log "Waiting for A0 /public_data ($url) ..."
  for attempt in $(seq 1 120); do
    curl -fsS "$url" >/dev/null 2>&1 && { pass "A0 back online"; return 0; }
    sleep 2
  done
  fatal "A0 did not come back online"
}

# ---------- subcommands ----------
cmd_prepare() {
  log "Tearing down any existing CVMs matching mpc-local-*"
  $CLI lsvm 2>/dev/null | awk '/mpc-local-/ {print $2}' | while read -r vm; do
    [ -n "$vm" ] || continue
    log "  stop+remove $vm"
    $CLI stop -f "$vm" 2>/dev/null || true
  done
  sleep 5
  $CLI lsvm 2>/dev/null | awk '/mpc-local-/ {print $2}' | while read -r vm; do
    [ -n "$vm" ] || continue
    $CLI remove "$vm" 2>/dev/null || true
  done

  log "Resetting localnet neard"
  pkill -9 neard 2>/dev/null || true
  sleep 1
  rm -rf "$HOME/.near/mpc-localnet"
  neard --home "$HOME/.near/mpc-localnet" init --chain-id mpc-localnet >/dev/null 2>&1
  cp -rf "$REPO_ROOT/deployment/localnet/." "$HOME/.near/mpc-localnet/"
  NEAR_ENV=mpc-localnet nohup neard --home "$HOME/.near/mpc-localnet" run >/tmp/neard.log 2>&1 &
  for attempt in 1 2 3 4 5 6 7 8; do
    if curl -sf http://127.0.0.1:3030/status 2>/dev/null | grep -q mpc-localnet; then
      pass "neard ready"
      break
    fi
    sleep 1
  done

  log "Delegating clean cluster deploy to $DEPLOY_SCRIPT (N=$N)"
  NO_PAUSE=1 FORCE_RECOLLECT=1 FORCE_REINIT_ARGS=1 \
    MPC_CONTRACT_ACCOUNT="$MPC_CONTRACT_ACCOUNT" \
    START_FROM_PHASE=preflight RESUME=0 \
    bash "$DEPLOY_SCRIPT"
  pass "Base cluster prepared (A0 + A1)"
}

cmd_status() {
  log "migration_info:"
  near_call_ro migration_info '{}' | extract_json_ro | jq . || true
  log "get_tee_accounts:"
  near_call_tx get_tee_accounts '{}' "$(node_account_for_i 0)" | extract_json_tx | jq . || true
  log "state (truncated):"
  near_call_ro state '{}' | extract_json_ro | jq '{state_keys: keys, participants: .Running.parameters.participants.participants}' || true
}

cmd_deploy_target() {
  deploy_target
  add_target_signer_key
  pass "Migration target ready"
}

# Clear backup-cli's cached keyshares (from a prior forward/back run). The
# `Refusing to overwrite existing permanent keyshares ...` safety check in
# `mpc-node`'s PermanentKeyStorage will trip otherwise. Preserve
# secrets.json (the backup-cli identity). Note:
# LocalPermanentKeyStorageBackend reads from $home_dir/key (top-level file),
# not from permanent_keys/ — must remove both.
clear_keyshare_cache() {
  if [ -e "$BACKUP_HOME_DIR/key" ] || [ -d "$BACKUP_HOME_DIR/permanent_keys" ]; then
    log "Clearing cached permanent keyshares at $BACKUP_HOME_DIR"
    rm -rf "$BACKUP_HOME_DIR/permanent_keys" "$BACKUP_HOME_DIR/key"
  fi
}

cmd_forward() {
  cmd_deploy_target
  ensure_backup_cli
  ensure_backup_keys
  register_backup_service
  clear_keyshare_cache
  do_get_keyshares "$B_SOURCE_INDEX"
  do_start_node_migration "$B_SOURCE_INDEX" "$B_INDEX"
  do_put_keyshares "$B_INDEX"
  wait_for_migration_completion "$B_SOURCE_INDEX" "$B_INDEX" || fatal "forward did NOT complete"
  verify_signing
  pass "Forward migration A0 -> B0 succeeded"
}

cmd_back() {
  # Pre-condition: forward completed (B0 is the participant, A0 is dormant).
  restart_source_node
  ensure_backup_cli
  ensure_backup_keys
  register_backup_service
  clear_keyshare_cache
  do_get_keyshares "$B_INDEX"             # source is now B0
  do_start_node_migration "$B_INDEX" "$B_SOURCE_INDEX"   # B -> A
  do_put_keyshares "$B_SOURCE_INDEX"
  if wait_for_migration_completion "$B_INDEX" "$B_SOURCE_INDEX"; then
    verify_signing
    pass "Back-migration B0 -> A0 succeeded (bug NOT reproduced on real-TDX localnet)"
  else
    err "Back-migration did not finalize"
    err "This is the empirical signal for near/mpc#2121 on real-TDX."
    cmd_status || true
    exit 1
  fi
}

cmd_both() {
  cmd_forward
  cmd_back
}

cmd_cleanup() {
  local vm; vm="$(vm_id_for "$B_INDEX" || true)"
  if [ -n "$vm" ]; then
    log "Removing migration target VM $vm"
    $CLI stop -f "$vm" 2>/dev/null || true
    sleep 2
    $CLI remove "$vm" 2>/dev/null || true
  else
    log "No migration target VM to remove"
  fi
  rm -rf "$BACKUP_HOME_DIR"
  rm -f "$WORKDIR/node${B_INDEX}.env" "$WORKDIR/node${B_INDEX}.toml" "$WORKDIR/node${B_INDEX}.keys.json"
  pass "Cleanup complete"
}

usage() {
  cat <<EOF
Usage: $0 <command>

Commands:
  prepare        Deploy a clean 2-node A0+A1 cluster via deploy-tee-cluster.sh
  deploy-target  Bring up B0 (third CVM sharing A0's account)
  forward        A0 -> B0 (deploys B0 if missing)
  back           B0 -> A0 (restarts A0 first)
  both           forward + back
  status         Dump migration_info + tee_accounts + participant set
  cleanup        Remove B0's CVM and tmp state

Env (required): MPC_NETWORK_BASE_NAME BASE_PATH
                MPC_MANIFEST_DIGEST LAUNCHER_MANIFEST_DIGEST
                (source set-localnet-env.sh first)

Env (optional): NEAR_NETWORK_CONFIG (=mpc-localnet)
                MPC_CONTRACT_ACCOUNT
                HOST_PROFILE (alice|bob)
                B_INDEX (=2), B_SOURCE_INDEX (=0)
                BACKUP_HOME_DIR, BACKUP_CLI
EOF
}

case "${1:-}" in
  prepare)        cmd_prepare ;;
  deploy-target)  cmd_deploy_target ;;
  forward)        cmd_forward ;;
  back)           cmd_back ;;
  both)           cmd_both ;;
  status)         cmd_status ;;
  cleanup)        cmd_cleanup ;;
  ""|-h|--help)   usage ;;
  *)              usage; exit 1 ;;
esac
