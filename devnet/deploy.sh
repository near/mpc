#!/bin/bash
set -exo pipefail

##########################################################################################
# Variable definition block
##########################################################################################

# Default values 
REDEPLOY=0
THRESHOLD=2
PARTICIPANTS=2
SUFFIX=$(uuidgen | tr '[:upper:]' '[:lower:]')
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SIGNER="signer-$SUFFIX.testnet"

##########################################################################################
# Function to display help
##########################################################################################

show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help           Display this help message"
    echo "  -r, --redeploy       Specify if redeploy of signer is required. O for false and 1 for true. (default: $REDEPLOY)"
    echo "  -t, --threshold      Specify a threshold for signing contract. (default: $THRESHOLD)"
    echo "  -p, --participants   Number of participants to generate. (default: $PARTICIPANTS)"
}
##########################################################################################
# Variable parsing block
##########################################################################################

while [ ! -z "$1" ]; do
   if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
      show_help; exit 0;
   elif [[ "$1" == "-r" ]] || [[ "$1" == "--redeploy" ]]; then
      REDEPLOY="$2"
      shift
   elif [[ $1 == "-t" ]] || [[ "$1" == "--threshold" ]]; then
      THRESHOLD="$2"
      shift
   elif [[ $1 == "-p" ]] || [[ "$1" == "--participants" ]]; then
      PARTICIPANTS="$2"
      shift
   else
      echo "Incorrect input provided $1"
      show_help; exit 0;
   fi
shift
done

##########################################################################################
# Functions block
##########################################################################################

compile_contract() {
    cd "$SCRIPT_DIR/../libs/mpc/chain-signatures"
    cargo build -p mpc-contract --target wasm32-unknown-unknown --release
    echo "$SCRIPT_DIR/../libs/mpc/target/wasm32-unknown-unknown/release/mpc_contract.wasm"
}

generate_key() {
    cd "$SCRIPT_DIR"
    if [ -e "devnet_configs/$1.json" ]; then
        echo "Key for participant $1 already exists"
        return
    fi

    cd "$SCRIPT_DIR/../libs/mpc/infra/scripts/generate_keys"

    # Output is like this:
    # cipher public key: a634485bc7f52339e867cd42d6f6cd02a691cf09a19ec5af97de6b563e9c9856
    # cipher private key: 167b7d58c219c40f927794470764d18245117fa70a7bf8839850f1744d91cba7
    # sign public key sign_pk: ed25519:Cukd8atjTKkwqPuTYiuPqqL36RoaqGkcDWWqPHoet3Ki
    # sign secret key sign_sk: ed25519:3gTxEoz6e8rzfVYuq3MH5K1DTTVnq7JV86Zo9PVVMdP4FYfDHMDX3b16krFBvFD3K3bjekMprE51U7Le1m9TuZ2L
    # near account public key: ed25519:DCnF4FvJ3JnozPAgAPqPt99JAkB71FQxBYmSLMvjMC75
    # near account secret key: ed25519:4TD46TdwQvxkT7SBCfooSTvt5tGbUnbVcNgZ4pShRgnPJsQ5h4wTYEWVkqAYMXeyuDzSBW43Tndr8HqPajTXMS3M
    # We need to write it in a json file
    KEYGEN_OUTPUT=$(cargo run)
    echo "$KEYGEN_OUTPUT"
    CIPHER_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*cipher public key: //p')
    CIPHER_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*cipher private key: //p')
    SIGN_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*sign public key sign_pk: //p')
    SIGN_SECRET_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*sign secret key sign_sk: //p')
    NEAR_ACCOUNT_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*near account public key: //p')
    NEAR_ACCOUNT_SECRET_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*near account secret key: //p')

    cd "$SCRIPT_DIR"
    mkdir -p devnet_configs
    echo "{
        \"cipher_public_key\": \"$CIPHER_PUBLIC_KEY\",
        \"cipher_private_key\": \"$CIPHER_PRIVATE_KEY\",
        \"sign_public_key\": \"$SIGN_PUBLIC_KEY\",
        \"sign_secret_key\": \"$SIGN_SECRET_KEY\",
        \"near_account_public_key\": \"$NEAR_ACCOUNT_PUBLIC_KEY\",
        \"near_account_secret_key\": \"$NEAR_ACCOUNT_SECRET_KEY\",
        \"url\": \"http://mpc-node-$1.service.mpc.consul:3000\"
    }" > devnet_configs/$1.json
}

hex_public_key_to_json_byte_array() {
    echo -n "["
    for i in $(seq 1 2 ${#1}); do
        echo -n "$((0x${1:i-1:2}))"
        [ $((i + 1)) -lt ${#1} ] && echo -n ","
    done
    echo "]"
}

##########################################################################################
# Main code block
##########################################################################################


near account create-account sponsor-by-faucet-service $SIGNER autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
if [ $REDEPLOY -eq 1 ]; then
    echo "Redeploying contract"
    if [ -d "$DIR" ]; then
        echo "Clearing existing configs directory"
        rm -rf "devnet_configs"
        
    fi
    near deploy $SIGNER "$(compile_contract)"
fi
for i in $(seq 0 $((PARTICIPANTS - 1))); do
    echo "Generating key for participant $i"
    generate_key $i
    near account create-account sponsor-by-faucet-service mpc-test$i-$SUFFIX.testnet use-manually-provided-public-key $(jq -r '.near_account_public_key' devnet_configs/$i.json) network-config testnet create
    # near account create-account fund-myself mpc-test$i-$SUFFIX.testnet '0.01 NEAR' use-manually-provided-public-key $(jq -r '.near_account_public_key' devnet_configs/$i.json) sign-as $SIGNER network-config testnet sign-with-legacy-keychain send
done


CANDIDATES="{
    $(for i in $(seq 0 $((PARTICIPANTS - 1))); do
        MPC_NAME=mpc-test$i-$SUFFIX.testnet
        echo "\"$MPC_NAME\": {
            \"account_id\": \"$MPC_NAME\",
            \"cipher_pk\": $(hex_public_key_to_json_byte_array $(jq -r '.cipher_public_key' devnet_configs/$i.json)),
            \"sign_pk\": \"$(jq -r '.sign_public_key' devnet_configs/$i.json)\",
            \"url\": \"$(jq -r '.url' devnet_configs/$i.json)\"
        }"
        if [ $((i + 1)) -lt $PARTICIPANTS ]; then echo ","; fi
    done)
}"

INIT_ARGS=$(jq -n --argjson candidates "$CANDIDATES" --argjson threshold "$THRESHOLD" '{ "candidates": $candidates, "threshold": $threshold }')

near call $SIGNER init "$INIT_ARGS" --use-account $SIGNER

# Initialize the JSON structure
nodes='{
  "mpc_nodes": [
'

for i in $(seq 0 $((PARTICIPANTS - 1))); do
  # Use jq to extract and format data for the current file
  node=$(jq --arg i "$i" --arg s "$SUFFIX" '
    {
      account: "mpc-test\($i)-\($s).testnet",
      account_pk: .near_account_public_key,
      account_sk: .near_account_secret_key,
      cipher_pk: .cipher_public_key,
      cipher_sk: .cipher_private_key,
      sign_sk: .sign_secret_key,
      url: .url
    }
  ' "devnet_configs/$i.json")

  if [ $((i + 1)) -lt $PARTICIPANTS ]
    then nodes+="$node,\n"
  else
    nodes+="$node\n"
  fi

done

nodes+="
  ],
  \"mpc_contract_signer\": \"signer-$SUFFIX.testnet\"
}"

echo -e "$nodes"| jq > devnet_configs/nodes.tfvars.json

echo "The signer account is $SIGNER."
echo "The signer account is required in the sign_request.sh script. Please retain it until the completion of the process."
echo "The script has generated the nodes.tfvars.json file."
echo "This should be used from Infra-Ops Terraform directories when starting Nomad cluster:"
echo "tf apply -var-file=\$path_to_nodes.tfvars.json"
echo "infra-ops/provisioning/nomad/mpc/"
echo "infra-ops/provisioning/terraform/infra/mpc/base-mpc-cluster"
