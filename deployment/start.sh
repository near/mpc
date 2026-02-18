#!/bin/bash
set -eo pipefail

# This script is intended to be used for running nearone/mpc.
# It will initialize the Near node in case it is not initialized yet and start the MPC node.

# --- Minimal hardening helpers ---
has_control_chars() {
  # Reject newline and carriage return. (NUL can't be represented well in bash, but we still check for CR/LF.)
  case "$1" in
    *$'\n'*|*$'\r'*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_clean_env() {
  local name="$1"
  local val="${!name}"
  if has_control_chars "$val"; then
    echo "ERROR: $name contains invalid control characters" >&2
    exit 1
  fi
}

# Validate env vars that are interpolated into YAML/Python snippets
require_clean_env "MPC_HOME_DIR"
require_clean_env "MPC_ENV"
require_clean_env "MPC_CONTRACT_ID"
require_clean_env "MPC_ACCOUNT_ID"
require_clean_env "NEAR_BOOT_NODES"
# Optional:
if [ -n "$MPC_RESPONDER_ID" ]; then
  require_clean_env "MPC_RESPONDER_ID"
fi

# In TEE (dstack), do NOT allow raw private keys to be provided via env.
if [ -n "$DSTACK_ENDPOINT" ]; then
  if [ -n "$MPC_P2P_PRIVATE_KEY" ] || [ -n "$MPC_ACCOUNT_SK" ]; then
    echo "ERROR: MPC_P2P_PRIVATE_KEY / MPC_ACCOUNT_SK must not be provided when running in TEE (DSTACK_ENDPOINT is set)" >&2
    exit 1
  fi
fi

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
    export NEAR_NODE_CONFIG_FILE
    export MPC_ENV
    export MPC_CONTRACT_ID

    python3 <<'EOF'
import json
import os

config_file = os.environ["NEAR_NODE_CONFIG_FILE"]
mpc_env = os.environ["MPC_ENV"]
contract_id = os.environ["MPC_CONTRACT_ID"]

config = json.load(open(config_file))

config['store']['load_mem_tries_for_tracked_shards'] = True

if mpc_env == "mpc-localnet":
    config['state_sync_enabled'] = False
else:
    # FAIL-FAST: crash if expected keys are missing (same behavior as before)
    config['state_sync']['sync']['ExternalStorage']['external_storage_fallback_threshold'] = 0

config['tracked_shards_config'] = {'Accounts': [contract_id]}

json.dump(config, open(config_file, 'w'), indent=2)
EOF
}



create_secrets_json_file() {
    local secrets_file="$1"

    export MPC_P2P_PRIVATE_KEY
    export MPC_ACCOUNT_SK

    python3 - "$secrets_file" <<'EOF'
import json
import os
import sys

secrets_file = sys.argv[1]
p2p_key_str = os.environ.get("MPC_P2P_PRIVATE_KEY", "")
account_sk_str = os.environ.get("MPC_ACCOUNT_SK", "")

if not p2p_key_str or not account_sk_str:
    print("Error: MPC_P2P_PRIVATE_KEY and MPC_ACCOUNT_SK must be provided", file=sys.stderr)
    sys.exit(1)

secrets = {
    "p2p_private_key": p2p_key_str,
    "near_signer_key": account_sk_str,
    "near_responder_keys": [account_sk_str]
}

with open(secrets_file, 'w') as f:
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
web_ui: 0.0.0.0:8080
migration_web_ui: 0.0.0.0:8079
pprof_bind_address: 0.0.0.0:34001
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

    if [ -f "$secrets_file" ]; then
        echo "secrets.json already exists, skipping generation"
        return 0
    fi

    if [ -z "$MPC_P2P_PRIVATE_KEY" ]; then
        if [ -n "$GCP_PROJECT_ID" ] && [ -n "$GCP_P2P_PRIVATE_KEY_SECRET_ID" ]; then
            echo "MPC_P2P_PRIVATE_KEY not provided in environment, fetching from GCP Secret Manager..."
            MPC_P2P_PRIVATE_KEY=$(gcloud secrets versions access latest --project "$GCP_PROJECT_ID" --secret="$GCP_P2P_PRIVATE_KEY_SECRET_ID")
            export MPC_P2P_PRIVATE_KEY
        fi
    else
        echo "Using provided MPC_P2P_PRIVATE_KEY from environment"
    fi

    if [ -z "$MPC_ACCOUNT_SK" ]; then
        if [ -n "$GCP_PROJECT_ID" ] && [ -n "$GCP_ACCOUNT_SK_SECRET_ID" ]; then
            echo "MPC_ACCOUNT_SK not provided in environment, fetching from GCP Secret Manager..."
            MPC_ACCOUNT_SK=$(gcloud secrets versions access latest --project "$GCP_PROJECT_ID" --secret="$GCP_ACCOUNT_SK_SECRET_ID")
            export MPC_ACCOUNT_SK
        fi
    else
        echo "Using provided MPC_ACCOUNT_SK from environment"
    fi

    if [ -n "$MPC_P2P_PRIVATE_KEY" ] && [ -n "$MPC_ACCOUNT_SK" ]; then
        echo "Generating secrets.json from provided keys..."
        if create_secrets_json_file "$secrets_file"; then
            echo "secrets.json created at $secrets_file"
        else
            echo "Failed to generate secrets.json" >&2
            return 1
        fi
    else
        echo "Skipping secrets.json generation - MPC_P2P_PRIVATE_KEY and/or MPC_ACCOUNT_SK not available"
    fi
}

if [ -r "$NEAR_NODE_CONFIG_FILE" ]; then
    echo "Near node is already initialized"
else
    echo "Initializing Near node"
    initialize_near_node "$MPC_HOME_DIR" && echo "Near node initialized"
fi

update_near_node_config && echo "Near node config updated"

if [ -r "$MPC_NODE_CONFIG_FILE" ]; then
    echo "MPC node is already initialized."
else
    echo "Initializing MPC node"
    initialize_mpc_config "$MPC_NODE_CONFIG_FILE" && echo "MPC node initialized"
fi

update_mpc_config "$MPC_NODE_CONFIG_FILE" && echo "MPC node config updated"

generate_secrets_json

if [ -z "$MPC_SECRET_STORE_KEY" ]; then
  echo "MPC_SECRET_STORE_KEY not provided in environment, will fetch from GCP Secret Manager..."
  MPC_SECRET_STORE_KEY=$(gcloud secrets versions access latest --project "$GCP_PROJECT_ID" --secret="$GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID")
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
/app/mpc-node start "$tee_authority"
