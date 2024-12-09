#!/bin/bash
SOURCE="nearone-robin.testnet"
SUFFIX="-test3"
PARTICIPANTS=2
THRESHOLD=2
REDEPLOY=1

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

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

near create-account --use-account $SOURCE --initial-balance 8 signer$SUFFIX.$SOURCE
if [ $REDEPLOY -eq 1 ]; then
    near deploy "signer$SUFFIX.$SOURCE" "$(compile_contract)"
fi
for i in $(seq 0 $((PARTICIPANTS - 1))); do
    generate_key $i
    near create-account --use-account $SOURCE --initial-balance 0.1 mpc-$i$SUFFIX.$SOURCE --public-key $(jq -r '.near_account_public_key' configs/$i.json)
done

hex_public_key_to_json_byte_array() {
    echo -n "["
    for i in $(seq 1 2 ${#1}); do
        echo -n "$((0x${1:i-1:2}))"
        [ $((i + 1)) -lt ${#1} ] && echo -n ","
    done
    echo "]"
}

CANDIDATES="{
    $(for i in $(seq 0 $((PARTICIPANTS - 1))); do
        echo "\"mpc-$i$SUFFIX.$SOURCE\": {
            \"account_id\": \"mpc-$i$SUFFIX.$SOURCE\",
            \"cipher_pk\": $(hex_public_key_to_json_byte_array $(jq -r '.cipher_public_key' configs/$i.json)),
            \"sign_pk\": \"$(jq -r '.sign_public_key' configs/$i.json)\",
            \"url\": \"$(jq -r '.url' configs/$i.json)\"
        }"
        [ $((i + 1)) -lt $PARTICIPANTS ] && echo ","
    done)
}"
echo $CANDIDATES


INIT_ARGS=$(jq -n --argjson candidates "$CANDIDATES" --argjson threshold "$THRESHOLD" '{ "candidates": $candidates, "threshold": $threshold }')

near call "signer$SUFFIX.$SOURCE" init "$INIT_ARGS" --use-account "signer$SUFFIX.$SOURCE"