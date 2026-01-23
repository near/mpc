#!/usr/bin/env bash
# Script to launch a localnet. The end result is a cluster of mpc-nodes
# with all domains added, ready to accept transactions.
#
# Requirements: jq envsubst near neard mpc-node
#
# Usage:
#   ./scripts/launch-localnet.sh [--mpc-contract-path <MPC_CONTRACT_PATH>] [--nodes <number_of_nodes>] [--threshold <threshold>]

set -euo pipefail

MPC_CONTRACT_PATH="./target/near/mpc_contract/mpc_contract.wasm"

# number of mpc-nodes in the network
N=2

# threshold, currently must be > 1 and at least 60% of N
THRESHOLD=2

# Base ports used by the mpc-nodes
# Currently mpc-node i uses port
# BASE_XXXX_PORT + i for functionality XXXX
# for example, mpc-node 2 uses 8082 as WEB_UI port
: "${BASE_RPC_PORT:=3030}"
: "${BASE_INDEXER_PORT:=24567}"
: "${BASE_WEB_UI_PORT:=8080}"
: "${BASE_MIGRATION_PORT:=9080}"
: "${BASE_PPROF_PORT:=34000}"
: "${BASE_P2P_PORT:=3000}"

cleanup() {
  echo "Running clean-up"
  read -rp "Press Enter to tear-down the processes..."
  for pid in "${pids[@]}"; do
    kill_process "${pid}"
  done

  read -rp "Press Enter to delete the logs..."
  if [[ -v tmpdir ]]; then
    rm -rf "${tmpdir}"
  fi

  echo "Script is exiting"
}

trap cleanup SIGINT SIGTERM EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
  --mpc-contract-path)
    MPC_CONTRACT_PATH="$2"
    shift 2
    ;;
  --nodes)
    N="$2"
    shift 2
    ;;
  --threshold)
    THRESHOLD="$2"
    shift 2
    ;;
  *)
    echo "Unknown parameter: $1"
    echo "Usage: $0 [--mpc-contract-path <MPC_CONTRACT_PATH>] [--nodes <number_of_nodes>] [--threshold <threshold>]"
    exit 1
    ;;
  esac
done

main() {
  require_cmds jq envsubst near neard mpc-node

  if [[ ! -f "$MPC_CONTRACT_PATH" ]]; then
    echo "$MPC_CONTRACT_PATH does not exist." >&2
    echo "The contract can be built by executing:" >&2
    echo "cargo near build non-reproducible-wasm --features abi --profile=release-contract --manifest-path crates/contract/Cargo.toml --locked" >&2
    exit 1
  fi

  pids=()
  tmpdir=$(mktemp -d /tmp/mpc-localnet.XXXXXX)

  echo "Using mpc-contract binary from ${MPC_CONTRACT_PATH}"
  echo "Creating network with ${N} mpc nodes and threshold ${THRESHOLD}"
  echo "Logs will be stored in ${tmpdir}"

  echo "Cleaning ~/.near folder"
  rm -rf ~/.near/

  neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet &>/dev/null
  cp -rf deployment/localnet/. ~/.near/mpc-localnet

  neard_cmd="NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run"
  neard_pid=$(run_bg "neard" "${neard_cmd}")
  pids+=("${neard_pid}")

  # Although this step does not take long, if the mpc-nodes are started
  # too fast, the blockchain halts
  NEARD_WAIT=60
  echo "Waiting ${NEARD_WAIT} seconds for neard to start properly"
  sleep $NEARD_WAIT

  neard_alive_cmd="curl -s localhost:3030/status | jq"
  wait_for_success "${neard_alive_cmd}"

  if ! grep -q "mpc-localnet" ~/.config/near-cli/config.toml; then
    echo "Not found. You need to add mpc-localnet config (shown below) to ~/.config/near-cli/config.toml"
    cat <<EOF
[network_connection.mpc-localnet]
network_name = "mpc-localnet"
rpc_url = "http://localhost:3030/"
wallet_url = "http://localhost:3030/"
explorer_transaction_url = "http://localhost:3030/"
linkdrop_account_id = "test.near"
EOF
    echo "For more details, see localnet guide"
    exit 1
  fi

  VALIDATOR_KEY=$(cat ~/.near/mpc-localnet/validator_key.json | jq ".secret_key" | grep -Eo "ed25519:\w+")
  NODE_PUBKEY=$(cat ~/.near/mpc-localnet/node_key.json | jq ".public_key" | grep -oE "ed25519:\w+")

  echo "Creating mpc-contract account"
  run_quiet_on_success "near account create-account fund-myself mpc-contract.test.near '1000 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key '$VALIDATOR_KEY' send"
  run_quiet_on_success "near account view-account-summary mpc-contract.test.near network-config mpc-localnet now"

  echo "Deploying mpc-contract"
  run_quiet_on_success "near contract deploy mpc-contract.test.near use-file '$MPC_CONTRACT_PATH' without-init-call network-config mpc-localnet sign-with-keychain send"
  run_quiet_on_success "near contract inspect mpc-contract.test.near network-config mpc-localnet now"

  echo "Creating mpc-node accounts"

  for ((i = 1; i <= N; i++)); do

    node_name="mpc-node-$i.test.near"
    run_quiet_on_success "near account create-account fund-myself ${node_name} '100 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send"

  done

  echo "Creating mpc nodes configuration"

  for ((i = 1; i <= N; i++)); do

    node_name="mpc-node-$i.test.near"
    mpc-node init --dir ~/.near/$node_name --chain-id mpc-localnet --genesis ~/.near/mpc-localnet/genesis.json --boot-nodes "$NODE_PUBKEY@0.0.0.0:24566"
    cp ~/.near/mpc-localnet/genesis.json ~/.near/$node_name/genesis.json
    RPC_PORT=$((BASE_RPC_PORT + i)) INDEXER_PORT=$((BASE_INDEXER_PORT + i)) jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' ~/.near/$node_name/config.json >~/.near/$node_name/tmp.json
    mv ~/.near/$node_name/tmp.json ~/.near/$node_name/config.json
    rm ~/.near/$node_name/validator_key.json

    WEB_UI_PORT=$((BASE_WEB_UI_PORT + i)) MIGRATION_PORT=$((BASE_MIGRATION_PORT + i)) PPROF_PORT=$((BASE_PPROF_PORT + i)) NEAR_ACCOUNT_NAME=$node_name envsubst <docs/localnet/mpc-configs/config.yaml.template >~/.near/$node_name/config.yaml

  done

  echo "Starting mpc nodes"

  for ((i = 1; i <= N; i++)); do

    node_name="mpc-node-$i.test.near"
    node_cmd="RUST_LOG=info mpc-node start --home-dir ~/.near/$node_name/ 11111111111111111111111111111111 --image-hash 8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0 --latest-allowed-hash-file /temp/LATEST_ALLOWED_HASH_FILE.txt local"
    node_pid=$(run_bg $node_name "${node_cmd}")
    pids+=("${node_pid}")
  done

  MPC_NODE_WAIT=20
  echo "Waiting ${MPC_NODE_WAIT} seconds for mpc nodes to start properly"
  sleep $MPC_NODE_WAIT

  echo "Adding account keys for the nodes"
  pids_adding_keys=()
  for ((i = 1; i <= N; i++)); do

    node_name="mpc-node-$i.test.near"

    NODE_PUBKEY=$(curl -s localhost:$((BASE_WEB_UI_PORT + i))/public_data | jq -r ".near_signer_public_key")
    NODE_RESPONDER_KEY=$(curl -s localhost:$((BASE_WEB_UI_PORT + i))/public_data | jq -r ".near_responder_public_keys[0]")

    run_quiet_on_success "near account add-key $node_name grant-full-access use-manually-provided-public-key $NODE_PUBKEY network-config mpc-localnet sign-with-keychain send" && \
    run_quiet_on_success "near account add-key $node_name grant-full-access use-manually-provided-public-key $NODE_RESPONDER_KEY network-config mpc-localnet sign-with-keychain send" &
    pids_adding_keys+=($!)
  done

  for pid in "${pids_adding_keys[@]}"; do
    wait "$pid"
  done

  JSON_RESULT=$(jq -n --arg threshold "$THRESHOLD" --arg next_id "$N" '
  {
    parameters: {
      threshold: ($threshold | tonumber),
      participants: {
        next_id: ($next_id | tonumber),
        participants: []
      }
    }
  }
')

  for ((i = 1; i <= N; i++)); do
    node_name="mpc-node-$i.test.near"
    node_p2p_key=$(curl -s localhost:$((BASE_WEB_UI_PORT + i))/public_data | jq -r '.near_p2p_public_key')
    node_url="https://localhost:$((BASE_P2P_PORT + i - 1))"

    JSON_RESULT=$(echo "$JSON_RESULT" | jq \
      --arg node_name "$node_name" \
      --arg node_id "$((i - 1))" \
      --arg node_p2p_key "$node_p2p_key" \
      --arg node_url "$node_url" \
      '.parameters.participants.participants += [[$node_name, ($node_id | tonumber), {sign_pk: $node_p2p_key, url: $node_url}]]')
  done

  init_args=$(mktemp /tmp/init_args.XXXXXX)
  echo "$JSON_RESULT" >"${init_args}"

  echo "Initializing contract"
  run_quiet_on_success "near contract call-function as-transaction mpc-contract.test.near init file-args ${init_args} prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as mpc-contract.test.near network-config mpc-localnet sign-with-keychain send"
  run_quiet_on_success "near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now"

  echo "Adding domains to contract"

  pids_adding_domains=()
  for ((i = 1; i <= N; i++)); do
    node_name="mpc-node-$i.test.near"
    run_quiet_on_success "near contract call-function as-transaction mpc-contract.test.near vote_add_domains file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as ${node_name} network-config mpc-localnet sign-with-keychain send" &
    pids_adding_domains+=($!)
  done

  for pid in "${pids_adding_domains[@]}"; do
    wait "$pid"
  done

  DOMAINS_WAIT=20
  echo "Waiting ${DOMAINS_WAIT} seconds for key generation to happen"
  sleep $DOMAINS_WAIT

  is_contract_running_cmd="near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now 2>&1 | grep Running"
  wait_for_success "${is_contract_running_cmd}"

  signer_account="mpc-node-1.test.near"

  echo "Executing signature requests"
  run_quiet_on_success "near contract call-function as-transaction mpc-contract.test.near sign file-args docs/localnet/args/sign_ecdsa.json prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' sign-as ${signer_account} network-config mpc-localnet sign-with-keychain send"
  run_quiet_on_success "near contract call-function as-transaction mpc-contract.test.near sign file-args docs/localnet/args/sign_eddsa.json prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' sign-as ${signer_account} network-config mpc-localnet sign-with-keychain send"
  run_quiet_on_success "near contract call-function as-transaction mpc-contract.test.near request_app_private_key file-args docs/localnet/args/ckd.json prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' sign-as ${signer_account} network-config mpc-localnet sign-with-keychain send"

  read -rp "Press Enter to finish the script and run clean-up steps..."
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

kill_process() {
  local pid="$1"

  if [[ -z "$pid" ]]; then
    echo "Error: No PID provided." >&2
    return 1
  fi

  if kill -0 "$pid" 2>/dev/null; then
    echo "Killing process $pid..."
    kill "$pid"
    echo "Process $pid terminated." >&2
  else
    echo "Warning: Process $pid does not exist. Skipping." >&2
  fi
}

run_bg() {
  local name="$1"
  local cmd="$2"
  local out_file
  local err_file

  out_file="${tmpdir}/${name}_stdout"
  err_file="${tmpdir}/${name}_stderr"

  bash -c "$cmd" >"$out_file" 2>"$err_file" &

  local pid=$!

  echo "Started: $name PID: $pid" >&2

  echo "$pid"
}

wait_for_success() {
  local cmd="$1"
  local sleep_time=2

  until eval "$cmd" >/dev/null; do
    echo "Command ${cmd} failed. Retrying in ${sleep_time}s..." >&2
    sleep ${sleep_time}
  done
}

run_quiet_on_success() {
  local cmd="$1"

  local tmp_stdout
  local tmp_stderr
  tmp_stdout=$(mktemp /tmp/cmd_stdout.XXXXXX)
  tmp_stderr=$(mktemp /tmp/cmd_stderr.XXXXXX)

  if eval "$cmd" >"$tmp_stdout" 2>"$tmp_stderr"; then
    rm "$tmp_stdout" "$tmp_stderr"
  else
    echo "FAILED: $cmd" >&2
    echo "-------------------------------------------" >&2
    echo "stdout:"
    cat "$tmp_stdout" >&2
    echo "-------------------------------------------" >&2
    echo "stderr:"
    cat "$tmp_stderr" >&2
    echo "-------------------------------------------" >&2
    rm "$tmp_stdout" "$tmp_stderr"
    return 1
  fi
}

main
