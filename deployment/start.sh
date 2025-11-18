#!/bin/bash
set -eo pipefail

# This script is intended to be used for running nearone/mpc.
# It will initialize the Near node in case it is not initialized yet and start the MPC node.

MPC_NODE_CONFIG_FILE="$MPC_HOME_DIR/config.yaml"
NEAR_NODE_CONFIG_FILE="$MPC_HOME_DIR/config.json"

initialize_near_node() {
    if [ "$MPC_ENV" = "mpc-localnet" ]; then
        EMBEDDED_GENESIS="/app/localnet-genesis.json"
        if [ ! -f "$EMBEDDED_GENESIS" ]; then
            echo "ERROR: Embedded localnet genesis file not found at $EMBEDDED_GENESIS"
            exit 1
        fi
        echo "Using embedded localnet genesis file"

        # boot_nodes must be filled in or else the node will not have any peers.
        ./mpc-node init --dir "$1" --chain-id "$MPC_ENV" --genesis "$EMBEDDED_GENESIS" --boot-nodes "$NEAR_BOOT_NODES"

        # The init command generates a modified genesis file for some reason, so we must hard-copy the original one.
        cp "$EMBEDDED_GENESIS" "$1/genesis.json"

        # Additionally, the init command will generate a `validator_key.json`
        # file which we can simply remove.
        rm "$1/validator_key.json"
    else
        echo "Downloading genesis file"
        # boot_nodes must be filled in or else the node will not have any peers.
        ./mpc-node init --dir "$1" --chain-id "$MPC_ENV" --download-genesis --download-config --boot-nodes "$NEAR_BOOT_NODES"
    fi
}

update_near_node_config() {
    python3 <<EOF
import json;
config = json.load(open("$NEAR_NODE_CONFIG_FILE"))

# boot nodes must be filled in or else the node will not have any peers.
config['store']['load_mem_tries_for_tracked_shards'] = True

if "$MPC_ENV" == "mpc-localnet":
    config['state_sync_enabled'] = False
else:
    config['state_sync']['sync']['ExternalStorage']['external_storage_fallback_threshold'] = 0

# Track whichever shard the contract account is on.
config['tracked_shards_config'] = {'Accounts': ["$MPC_CONTRACT_ID"]}
json.dump(config, open("$NEAR_NODE_CONFIG_FILE", 'w'), indent=2)
EOF
}

create_secrets_json_file() {
    python3 <<EOF
import json;

p2p_key_str = "${MPC_P2P_PRIVATE_KEY}"
account_sk_str = "${MPC_ACCOUNT_SK}"

if not p2p_key_str or not account_sk_str:
    print("Error: MPC_P2P_PRIVATE_KEY and MPC_ACCOUNT_SK must be provided", file=sys.stderr)
    sys.exit(1)

secrets = {
    "p2p_private_key": p2p_key_str,
    "near_signer_key": account_sk_str,
    "near_responder_keys": [account_sk_str]
}

# Write to secrets.json
with open("$secrets_file", 'w') as f:
    json.dump(secrets, f, indent=2)

print("secrets.json generated successfully")
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
migration_web_ui:
  host: 0.0.0.0
  port: 8079
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
ckd:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: $MPC_CONTRACT_ID
  finality: optimistic
cores: 12
EOF

    # Add port_override for non-localnet environments
    if [ "$MPC_ENV" != "mpc-localnet" ]; then
        sed -i '/mpc_contract_id:/a\  port_override: 80' "$1"
    fi
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

generate_secrets_json() {
    local secrets_file="$MPC_HOME_DIR/secrets.json"

    # Skip if secrets.json already exists
    if [ -f "$secrets_file" ]; then
        echo "secrets.json already exists, skipping generation"
        return 0
    fi

    # Check if MPC_P2P_PRIVATE_KEY is empty - if so, fetch from GCP Secret Manager
    if [ -z "${MPC_P2P_PRIVATE_KEY}" ]; then
        if [ -n "${GCP_PROJECT_ID}" ] && [ -n "${GCP_P2P_PRIVATE_KEY_SECRET_ID}" ]; then
            echo "MPC_P2P_PRIVATE_KEY not provided in environment, fetching from GCP Secret Manager..."
            MPC_P2P_PRIVATE_KEY=$(gcloud secrets versions access latest --project "$GCP_PROJECT_ID" --secret="$GCP_P2P_PRIVATE_KEY_SECRET_ID")
            export MPC_P2P_PRIVATE_KEY
        fi
    else
        echo "Using provided MPC_P2P_PRIVATE_KEY from environment"
    fi

    # Check if MPC_ACCOUNT_SK is empty - if so, fetch from GCP Secret Manager
    if [ -z "${MPC_ACCOUNT_SK}" ]; then
        if [ -n "${GCP_PROJECT_ID}" ] && [ -n "${GCP_ACCOUNT_SK_SECRET_ID}" ]; then
            echo "MPC_ACCOUNT_SK not provided in environment, fetching from GCP Secret Manager..."
            MPC_ACCOUNT_SK=$(gcloud secrets versions access latest --project "$GCP_PROJECT_ID" --secret="$GCP_ACCOUNT_SK_SECRET_ID")
            export MPC_ACCOUNT_SK
        fi
    else
        echo "Using provided MPC_ACCOUNT_SK from environment"
    fi

    # Only generate secrets.json if we have the required keys
    if [ -n "${MPC_P2P_PRIVATE_KEY}" ] && [ -n "${MPC_ACCOUNT_SK}" ]; then
        echo "Generating secrets.json from provided keys..."
        if create_secrets_json_file; then
            echo "secrets.json created at $secrets_file"
        else
            echo "Failed to generate secrets.json" >&2
            return 1
        fi
    else
        echo "Skipping secrets.json generation - MPC_P2P_PRIVATE_KEY and/or MPC_ACCOUNT_SK not available"
    fi
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

# Generate secrets.json from environment variables if needed (for 2.2.0 -> 3.0.0 upgrade)
generate_secrets_json

# Check if MPC_SECRET_STORE_KEY is empty - if so, fetch from GCP Secret Manager
if [ -z "${MPC_SECRET_STORE_KEY}" ]; then
  echo "MPC_SECRET_STORE_KEY not provided in environment, will fetch from GCP Secret Manager..."
  MPC_SECRET_STORE_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID)
  export MPC_SECRET_STORE_KEY
else
  echo "Using provided MPC_SECRET_STORE_KEY from environment"
fi

if [ -n "$DSTACK_ENDPOINT" ]; then
    tee_authority=dstack
else
    tee_authority=local
fi

echo "Starting mpc node..."
/app/mpc-node start $tee_authority
