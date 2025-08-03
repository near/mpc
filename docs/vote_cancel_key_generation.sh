#!/bin/bash

if [ $# -eq 1 ]; then
    # Set DOMAIN_ID to first argument
    DOMAIN_ID="$1"
else
    # Exit with error message
    echo "Error: Please provide exactly one argument (domain_id)"
    echo "Usage: $0 <domain_id>"
    exit 1
fi

# Default signers
SIGNERS=("alice.test.near" "bob.test.near")

echo "Voting to cancel key resharing for domain ID: $DOMAIN_ID"
echo "Using signers: ${SIGNERS[*]}"
echo

# Loop through each signer
for SIGNER in "${SIGNERS[@]}"; do
    echo "--- Voting as: $SIGNER ---"
    
    near contract \
        call-function \
        as-transaction \
        mpc-contract.test.near \
        vote_cancel_keygen \
        json-args "{\"next_domain_id\": $DOMAIN_ID}" \
        prepaid-gas '300.0 Tgas' \
        attached-deposit '0 NEAR' \
        sign-as "$SIGNER" \
        network-config mpc-localnet \
        sign-with-keychain \
        send
    
    echo
done

echo "Completed voting for all signers!"