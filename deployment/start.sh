#!/bin/bash
set -eo pipefail

# This script is intended to be used for running nearone/mpc in a GCP environment.
# It will initialize the Near node in case it is not initialized yet and start the MPC node.

MPC_NODE_CONFIG_FILE="$MPC_HOME_DIR/config.yaml"
NEAR_NODE_CONFIG_FILE="$MPC_HOME_DIR/config.json"

initialize_near_node() {
    # boot_nodes must be filled in or else the node will not have any peers.
    ./mpc-node init --dir "$1" --chain-id "$MPC_ENV" --download-genesis --download-config --boot-nodes "$NEAR_BOOT_NODES"
}

update_near_node_config() {
      python3 <<EOF
import json;
config = json.load(open("$NEAR_NODE_CONFIG_FILE"))

# boot nodes must be filled in or else the node will not have any peers.
config['store']['load_mem_tries_for_tracked_shards'] = True
config['state_sync']['sync']['ExternalStorage']['external_storage_fallback_threshold'] = 0

# Track whichever shard the contract account is on.
config['tracked_shards_config'] = {'Accounts': ["$MPC_CONTRACT_ID"]}
json.dump(config, open("$NEAR_NODE_CONFIG_FILE", 'w'), indent=2)
EOF
}

initialize_mpc_config() {

    if [ -n "$MPC_RESPONDER_ID" ]; then
        responder_id="$MPC_RESPONDER_ID"
    else
        echo "WARNING: \$MPC_RESPONDER_ID is not set, falling back to \$MPC_ACCOUNT_ID"
        responder_id="$MPC_ACCOUNT_ID"
    fi

    cat <<EOF >"$1"
# Configuration File
my_near_account_id: $MPC_ACCOUNT_ID
near_responder_account_id: $responder_id
number_of_responder_keys: 50
web_ui:
  host: 0.0.0.0
  port: 8080
triple:
  concurrency: 2
  desired_triples_to_buffer: 1000000
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 16
  desired_presignatures_to_buffer: 8192
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: $MPC_CONTRACT_ID
  port_override: 80
  finality: optimistic
cores: 12
EOF
}

update_mpc_config() {
  # Use sed to replace placeholder values
  sed -i "s/my_near_account_id:.*/my_near_account_id: $MPC_ACCOUNT_ID/" "$1"
  sed -i "s/mpc_contract_id:.*/mpc_contract_id: $MPC_CONTRACT_ID/" "$1"

  if [ -n "$MPC_RESPONDER_ID" ]; then
      responder_id="$MPC_RESPONDER_ID"
    else
      echo "WARNING: \$MPC_RESPONDER_ID is not set, falling back to \$MPC_ACCOUNT_ID"
      responder_id="$MPC_ACCOUNT_ID"
  fi
  sed -i "s/near_responder_account_id:.*/near_responder_account_id: $responder_id/" "$1"
}

# Check and initialize Near node config if needed
if [ -r "$NEAR_NODE_CONFIG_FILE" ]; then
    echo "Near node is already initialized"
else
    echo "Initializing Near node"
    initialize_near_node "$MPC_HOME_DIR" && echo "Near node initialized"
fi

# Update the Near node config with the MPC ENV variables values
update_near_node_config && echo "Near node config updated"


# Check and initialize MPC config if needed
if [ -r "$MPC_NODE_CONFIG_FILE" ]; then
    echo "MPC node is already initialized."
else
    echo "Initializing MPC node"
    initialize_mpc_config "$MPC_NODE_CONFIG_FILE" && echo "MPC node initialized"
fi

update_mpc_config "$MPC_NODE_CONFIG_FILE" && echo "MPC node config updated"


# Check if MPC_SECRET_STORE_KEY is empty - if so, fetch from GCP Secret Manager
if [ -z "${MPC_SECRET_STORE_KEY}" ]; then
    echo "MPC_SECRET_STORE_KEY not provided in environment, will fetch from GCP Secret Manager..."
    export MPC_SECRET_STORE_KEY=$(gcloud secrets versions access latest --project "$GCP_PROJECT_ID" --secret="$GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID")
else
    echo "Using provided MPC_SECRET_STORE_KEY from environment"
fi

echo "Starting mpc node..."
/app/mpc-node start
