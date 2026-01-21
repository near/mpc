#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${LOCALNET_CONFIG:-/config/localnet.config.json}"
SEED_DIR="${SEED_DIR:-/seed}"
NEAR_RPC_URL="${NEAR_RPC_URL:-http://neard:3030/}"
MPC_CONTRACT_PATH="${MPC_CONTRACT_PATH:-}"

require_cmds() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing dependency: $cmd" >&2; missing=1; }
  done
  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
}

wait_for() {
  local cmd="$1"
  local sleep_time=2
  until eval "$cmd" >/dev/null 2>&1; do
    echo "Waiting for: $cmd" >&2
    sleep "$sleep_time"
  done
}

run_allow_fail() {
  local cmd="$1"
  if ! eval "$cmd"; then
    echo "WARN: command failed (continuing): $cmd" >&2
  fi
}

require_cmds jq curl near

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config not found: $CONFIG_PATH" >&2
  exit 1
fi

CHAIN_ID=$(jq -r '.chain_id' "$CONFIG_PATH")
CONTRACT_ID=$(jq -r '.contract_id' "$CONFIG_PATH")
VALIDATOR_ACCOUNT_ID=$(jq -r '.validator_account_id' "$CONFIG_PATH")
THRESHOLD=$(jq -r '.threshold' "$CONFIG_PATH")
NODE_COUNT=$(jq -r '.nodes | length' "$CONFIG_PATH")

if [[ -z "$MPC_CONTRACT_PATH" ]]; then
  MPC_CONTRACT_PATH=$(jq -r '.bootstrap.contract_path' "$CONFIG_PATH")
fi

if [[ ! -f "$MPC_CONTRACT_PATH" ]]; then
  echo "Contract wasm not found at $MPC_CONTRACT_PATH" >&2
  exit 1
fi

VALIDATOR_KEY=$(jq -r '.secret_key' "$SEED_DIR/validator_key.json")

mkdir -p /root/.config/near-cli
cat > /root/.config/near-cli/config.toml <<EOF_NEAR
[network_connection.${CHAIN_ID}]
network_name = "${CHAIN_ID}"
rpc_url = "${NEAR_RPC_URL}"
wallet_url = "${NEAR_RPC_URL}"
explorer_transaction_url = "${NEAR_RPC_URL}"
linkdrop_account_id = "${VALIDATOR_ACCOUNT_ID}"
EOF_NEAR

wait_for "curl -s ${NEAR_RPC_URL}status | jq -e .version"

ensure_account() {
  local account_id="$1"
  local amount="$2"
  if near account view-account-summary "$account_id" network-config "$CHAIN_ID" now >/dev/null 2>&1; then
    echo "Account exists: $account_id" >&2
    return 0
  fi

  near account create-account fund-myself "$account_id" "$amount" \
    autogenerate-new-keypair save-to-legacy-keychain \
    sign-as "$VALIDATOR_ACCOUNT_ID" network-config "$CHAIN_ID" \
    sign-with-plaintext-private-key "$VALIDATOR_KEY" send
}

ensure_account "$CONTRACT_ID" "1000 NEAR"

if ! near contract inspect "$CONTRACT_ID" network-config "$CHAIN_ID" now >/dev/null 2>&1; then
  echo "Deploying contract to $CONTRACT_ID" >&2
  near contract deploy "$CONTRACT_ID" use-file "$MPC_CONTRACT_PATH" \
    without-init-call network-config "$CHAIN_ID" sign-with-keychain send
fi

for ((i=0; i<NODE_COUNT; i++)); do
  node_account=$(jq -r ".nodes[$i].account_id" "$CONFIG_PATH")
  ensure_account "$node_account" "100 NEAR"
  node_service=$(jq -r ".nodes[$i].service_name // .nodes[$i].name" "$CONFIG_PATH")

  public_data_url=$(jq -r ".nodes[$i].public_data_url // empty" "$CONFIG_PATH")
  if [[ -z "$public_data_url" || "$public_data_url" == "null" ]]; then
    public_data_url="http://${node_service}:8080/public_data"
  fi

  wait_for "curl -s ${public_data_url} | jq -e .near_signer_public_key"

  NODE_PUBKEY=$(curl -s "$public_data_url" | jq -r '.near_signer_public_key')
  NODE_RESPONDER_KEY=$(curl -s "$public_data_url" | jq -r '.near_responder_public_keys[0]')

  run_allow_fail "near account add-key $node_account grant-full-access use-manually-provided-public-key $NODE_PUBKEY network-config $CHAIN_ID sign-with-keychain send"
  run_allow_fail "near account add-key $node_account grant-full-access use-manually-provided-public-key $NODE_RESPONDER_KEY network-config $CHAIN_ID sign-with-keychain send"

done

JSON_RESULT=$(jq -n --arg threshold "$THRESHOLD" --arg next_id "$NODE_COUNT" '
  {
    parameters: {
      threshold: ($threshold | tonumber),
      participants: {
        next_id: ($next_id | tonumber),
        participants: []
      }
    }
  }')

for ((i=0; i<NODE_COUNT; i++)); do
  node_account=$(jq -r ".nodes[$i].account_id" "$CONFIG_PATH")
  node_service=$(jq -r ".nodes[$i].service_name // .nodes[$i].name" "$CONFIG_PATH")
  public_data_url=$(jq -r ".nodes[$i].public_data_url // empty" "$CONFIG_PATH")
  if [[ -z "$public_data_url" || "$public_data_url" == "null" ]]; then
    public_data_url="http://${node_service}:8080/public_data"
  fi
  node_p2p_key=$(curl -s "$public_data_url" | jq -r '.near_p2p_public_key')

  node_url=$(jq -r ".nodes[$i].p2p_url // empty" "$CONFIG_PATH")
  if [[ -z "$node_url" || "$node_url" == "null" ]]; then
    node_url="https://${node_service}:3000"
  fi

  JSON_RESULT=$(echo "$JSON_RESULT" | jq \
    --arg node_name "$node_account" \
    --arg node_id "$i" \
    --arg node_p2p_key "$node_p2p_key" \
    --arg node_url "$node_url" \
    '.parameters.participants.participants += [[$node_name, ($node_id | tonumber), {sign_pk: $node_p2p_key, url: $node_url}]]')

done

init_args=$(mktemp /tmp/init_args.XXXXXX)
echo "$JSON_RESULT" >"$init_args"

run_allow_fail "near contract call-function as-transaction $CONTRACT_ID init file-args $init_args prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as $CONTRACT_ID network-config $CHAIN_ID sign-with-keychain send"

for ((i=0; i<NODE_COUNT; i++)); do
  node_account=$(jq -r ".nodes[$i].account_id" "$CONFIG_PATH")
  run_allow_fail "near contract call-function as-transaction $CONTRACT_ID vote_add_domains file-args /work/docs/args/add_domain.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as $node_account network-config $CHAIN_ID sign-with-keychain send"

done

run_allow_fail "near contract call-function as-read-only $CONTRACT_ID state json-args {} network-config $CHAIN_ID now"

echo "Bootstrap finished" >&2
