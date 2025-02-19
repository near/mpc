#!/bin/bash
set -exo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Check if argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <candidate_index>"
    exit 1
fi

INDEX=$1
NODES_CONFIG="devnet_configs/nodes.tfvars.json"

# Load existing deployment info
if [ ! -f "$NODES_CONFIG" ]; then
    echo "Error: No existing deployment found. Run deploy.sh first to initialize the cluster."
    exit 1
fi

SUFFIX=$(jq -r '.nodes_uuid' "$NODES_CONFIG")
SIGNER=$(jq -r '.mpc_contract_signer' "$NODES_CONFIG")
CANDIDATE="mpc-test${INDEX}-${SUFFIX}.testnet"
EXISTING_NODES=$(jq -r '.mpc_nodes[] | select(.account != "'"$CANDIDATE"'")' "$NODES_CONFIG")

# Issue vote_join commands for each existing node
echo "$EXISTING_NODES" | jq -c '.' | while read -r node; do
    MPC_NAME=$(echo "$node" | jq -r '.account')
    ACCOUNT_PK=$(echo "$node" | jq -r '.account_pk')
    ACCOUNT_SK=$(echo "$node" | jq -r '.account_sk')
    
    echo "Voting from node: $MPC_NAME"
    near contract call-function as-transaction "$SIGNER" vote_join json-args "{ \"candidate\": \"$CANDIDATE\" }" \
        prepaid-gas '50.0 Tgas' \
        attached-deposit '0 NEAR' \
        sign-as "$MPC_NAME" \
        network-config testnet \
        sign-with-plaintext-private-key \
        --signer-public-key "$ACCOUNT_PK" \
        --signer-private-key "$ACCOUNT_SK" \
        send
done

echo "Completed voting process for candidate: $CANDIDATE" 