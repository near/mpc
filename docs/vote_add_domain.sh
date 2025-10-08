#!/bin/bash

# Script to vote on adding domains with multiple signers
# Usage: ./vote_domains.sh <domain_id> [signer1] [signer2] [signer3] ...
# If no signers provided after domain_id, defaults to frodo and sam

# Check if at least one argument (domain_id) is provided
if [ $# -eq 0 ]; then
    echo "Error: Please provide at least one argument (domain_id)"
    echo "Usage: $0 <domain_id> [signer1] [signer2] ..."
    exit 1
fi

# First argument is the domain ID
DOMAIN_ID="$1"
shift  # Remove first argument, rest are signers

# Default signers if none provided after domain_id
if [ $# -eq 0 ]; then
    SIGNERS=("frodo.test.near" "sam.test.near")
else
    SIGNERS=("$@")
fi

# Create JSON args with the domain ID
JSON_ARGS="{
    \"domains\": [
        {
            \"id\": $DOMAIN_ID,
            \"scheme\": \"Secp256k1\"
        }
    ]
}"

echo "Voting to add domain ID $DOMAIN_ID with ${#SIGNERS[@]} signers: ${SIGNERS[*]}"
echo "JSON args: $JSON_ARGS"
echo

# Loop through each signer
for SIGNER in "${SIGNERS[@]}"; do
    echo "--- Voting as: $SIGNER ---"
    
    near contract \
        call-function \
        as-transaction \
        mpc-contract.test.near \
        vote_add_domains \
        json-args "$JSON_ARGS" \
        prepaid-gas '300.0 Tgas' \
        attached-deposit '0 NEAR' \
        sign-as "$SIGNER" \
        network-config mpc-localnet \
        sign-with-keychain \
        send
    
    echo
done

echo "Completed voting for all signers!"
