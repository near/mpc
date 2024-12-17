#!/bin/bash
set -exo pipefail

##########################################################################################
# Variable definition block
##########################################################################################

# SOURCE="nearone-robin.testnet"
SUFFIX=$(uuidgen)

REDEPLOY=$1
THRESHOLD=$2
PARTICIPANTS=$3
ZONE=$4

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"


##########################################################################################
# Temp debug block - TODO DELETE IT 
##########################################################################################

# locals {
#   old_mpc_nodes = [
#     {
#         account              = "mpc-test0-test-key-generation0011111111111.testnet"
#         cipher_pk            = "9b6a39f87edd287a54430a2a49ba17cc707a75ee85085fe00800a18a1794127b"
#         account_sk = "ed25519:3ZVYRDC785uX9NgzUt1tWqwimaKxK36ge9NVrEVpy75Mkqt2kx12efeduAfLw8Dx3nWPj82X9mzGeTxLbNXysEAW"
#         cipher_sk  = "8425790a303989b72fbceee2dd81c5c054d81c21d27a850fda837b1504b045d1"
#         sign_sk    = "ed25519:668vJprWzofjZRUJfsn58jyov8fXVWMLaacott6raWThLPt7SyzUWmEVyDz6tusPCZRWgLzjzhwMcsjuzJXuLSyE"
#     },
#     {
#         account              = "mpc-test1-test-key-generation0011111111111.testnet"
#         cipher_pk            = "a3fbc5dec8e2fc3e3be7a0796778940c1e5dcfa0ffa3995caab72d6269278e2b"
#         account_sk = "ed25519:N9HsLP7XLcep6GzU7UsA4eWscogkcefTnChxer19Z5DQAAT8PopovNGeXvZQpKWqbGhJwGPnKkXDtNX3G4p8td3"
#         cipher_sk  = "4b7d2c904ee76763044ffdd328348bbabeaf6e82752a3bffc15481668f38ccca"
#         sign_sk    = "ed25519:4Wwrcp3Qb45bR8EabqMpGx5DS9jWdwQ5UZQJanToXdkZV6QdEj1mK6ntd9vUPVP4EuejfztFSvUGZdJSjXnpDrTL"
#     },
#   ]
#   upgraded_mpc_nodes = [
#     {
#         "p2p_public_key": "7651c69c0826a3bb4091186066d489f48f8099106e18e736e0c156c8a2c0c344",
#     },
#     {
#         "p2p_public_key": "2aa60bf15e7f584e7e19b1c160ef13b06255f655bb173d2e5935e3658c28da36",
#     }
#   ]
#   mpc_contract = "signer-test-key-generation0011111111111.testnet"
# }

# Current output
# { 
#     "mpc-test0-0af63531-5195-437c-b158-3a257e2f7caa.testnet": { 
#     "account_id": "mpc-test0-0af63531-5195-437c-b158-3a257e2f7caa.testnet", 
#     "cipher_pk": [155,106,57,248,126,221,40,122,84,67,10,42,73,186,23,204,112,122,117,238,133,8,95,224,8,0,161,138,23,148,18,123], 
#     "sign_pk": "ed25519:GeqmQKHHZVzYTXTysee31YjQx4MEBFoZRtZda2SBLSRE", 
#     "url": "http://old-mpc-node-0.service.mpc.consul:3000" 
#     } , 
#     "mpc-test1-0af63531-5195-437c-b158-3a257e2f7caa.testnet": {
#      "account_id": "mpc-test1-0af63531-5195-437c-b158-3a257e2f7caa.testnet", 
#      "cipher_pk": [163,251,197,222,200,226,252,62,59,231,160,121,103,120,148,12,30,93,207,160,255,163,153,92,170,183,45,98,105,39,142,43], 
#      "sign_pk": "ed25519:HLVhoaoYKw9GXVDtckqhnUhd4UR5qmqGh1zDmeq2tMrS", 
#      "url": "http://old-mpc-node-1.service.mpc.consul:3000" 
#      }      
# }


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
    if [ -e "configs/$1.json" ]; then
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
    echo $KEYGEN_OUTPUT
    CIPHER_PUBLIC_KEY=$(echo $KEYGEN_OUTPUT | grep -oP 'cipher public key: \K[0-9a-f]+')
    CIPHER_PRIVATE_KEY=$(echo $KEYGEN_OUTPUT | grep -oP 'cipher private key: \K[0-9a-f]+')
    SIGN_PUBLIC_KEY=$(echo $KEYGEN_OUTPUT | grep -oP 'sign public key sign_pk: \Ked25519:[0-9a-zA-Z]+')
    SIGN_SECRET_KEY=$(echo $KEYGEN_OUTPUT | grep -oP 'sign secret key sign_sk: \Ked25519:[0-9a-zA-Z]+')
    NEAR_ACCOUNT_PUBLIC_KEY=$(echo $KEYGEN_OUTPUT | grep -oP 'near account public key: \Ked25519:[0-9a-zA-Z]+')
    NEAR_ACCOUNT_SECRET_KEY=$(echo $KEYGEN_OUTPUT | grep -oP 'near account secret key: \Ked25519:[0-9a-zA-Z]+')

    cd "$SCRIPT_DIR"
    mkdir -p configs
    echo "{
        \"cipher_public_key\": \"$CIPHER_PUBLIC_KEY\",
        \"cipher_private_key\": \"$CIPHER_PRIVATE_KEY\",
        \"sign_public_key\": \"$SIGN_PUBLIC_KEY\",
        \"sign_secret_key\": \"$SIGN_SECRET_KEY\",
        \"near_account_public_key\": \"$NEAR_ACCOUNT_PUBLIC_KEY\",
        \"near_account_secret_key\": \"$NEAR_ACCOUNT_SECRET_KEY\",
        \"url\": \"http://old-mpc-node-$1.service.mpc.consul:3000\"
    }" > configs/$1.json
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


near account create-account sponsor-by-faucet-service signer-$SUFFIX.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
if [ $REDEPLOY -eq 1 ]; then
    near deploy "signer-$SUFFIX.testnet" "$(compile_contract)"
fi
echo $PARTICIPANTS
for i in $(seq 0 $((PARTICIPANTS - 1))); do
    generate_key $i
    near account create-account sponsor-by-faucet-service mpc-test$i-$SUFFIX.testnet use-manually-provided-public-key $(jq -r '.near_account_public_key' configs/$i.json) network-config testnet create
    # near account create-account mpc-test$i-$SUFFIX.testnet use-manually-provided-public-key $(jq -r '.near_account_public_key' configs/$i.json) network-config testnet create
done


CANDIDATES="{
    $(for i in $(seq 0 $((PARTICIPANTS - 1))); do
        MPC_NAME=mpc-test$i-$SUFFIX.testnet
        echo "\"$MPC_NAME\": {
            \"account_id\": \"$MPC_NAME\",
            \"cipher_pk\": $(hex_public_key_to_json_byte_array $(jq -r '.cipher_public_key' configs/$i.json)),
            \"sign_pk\": \"$(jq -r '.sign_public_key' configs/$i.json)\",
            \"url\": \"$(jq -r '.url' configs/$i.json)\"
        }"
        [ $((i + 1)) -lt $PARTICIPANTS ] && echo ","
    done)
}"
echo $CANDIDATES
echo ""


#     {
#         account              = "mpc-test0-test-key-generation0011111111111.testnet"
#         account_sk = "ed25519:3ZVYRDC785uX9NgzUt1tWqwimaKxK36ge9NVrEVpy75Mkqt2kx12efeduAfLw8Dx3nWPj82X9mzGeTxLbNXysEAW"
#         cipher_pk            = "9b6a39f87edd287a54430a2a49ba17cc707a75ee85085fe00800a18a1794127b"
#         cipher_sk  = "8425790a303989b72fbceee2dd81c5c054d81c21d27a850fda837b1504b045d1"
#         sign_sk    = "ed25519:668vJprWzofjZRUJfsn58jyov8fXVWMLaacott6raWThLPt7SyzUWmEVyDz6tusPCZRWgLzjzhwMcsjuzJXuLSyE"
#     },


# TODO FINISH FORMATED CANDIDATES
FORMATED_CANDIDATES="{
    $(for i in $(seq 0 $((PARTICIPANTS - 1))); do
        MPC_NAME=mpc-test$i-$SUFFIX.testnet
        echo "{
            account: \"$MPC_NAME\",
            account_sk: \"$(jq -r '.near_account_secret_key' configs/$i.json)\",
            cipher_pk: \"$(jq -r '.cipher_public_key' configs/$i.json)\",
            cipher_sk: \"$(jq -r '.cipher_private_key' configs/$i.json)\",
            sign_sk: \"$(jq -r '.sign_secret_key' configs/$i.json)\"
        }"
        [ $((i + 1)) -lt $PARTICIPANTS ] && echo ","
    done)
}, mpc_contract = \"signer-$SUFFIX.testnet\","
echo $FORMATED_CANDIDATES
echo ""

INIT_ARGS=$(jq -n --argjson candidates "$CANDIDATES" --argjson threshold "$THRESHOLD" '{ "candidates": $candidates, "threshold": $threshold }')

near call "signer-$SUFFIX.testnet" init "$INIT_ARGS" --use-account "signer-$SUFFIX.testnet"