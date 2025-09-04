#!/bin/bash

# Script to automate NEAR account key assignment
# Usage: ./assign-near-keys.sh <name> <port>
# Example: ./assign-near-keys.sh alice 8081

set -e  # Exit on error

# Check if required arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <name> <port>"
    echo "Example: $0 alice 8081"
    exit 1
fi

NAME=$1
PORT=$2
ACCOUNT_NAME="${NAME}.test.near"

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting key assignment for ${ACCOUNT_NAME} on port ${PORT}...${NC}\n"

# Fetch public data from the specified port
echo -e "${GREEN}Fetching public data from localhost:${PORT}...${NC}"
PUBLIC_DATA=$(curl -s "localhost:${PORT}/public_data")

if [ -z "$PUBLIC_DATA" ]; then
    echo -e "${RED}Error: Failed to fetch public data from localhost:${PORT}${NC}"
    exit 1
fi

# Display the fetched data
echo -e "${GREEN}Public data retrieved:${NC}"
echo "$PUBLIC_DATA" | jq '.' || echo "$PUBLIC_DATA"
echo ""

# Extract the signer public key
SIGNER_KEY=$(echo "$PUBLIC_DATA" | jq -r '.near_signer_public_key')

if [ "$SIGNER_KEY" == "null" ] || [ -z "$SIGNER_KEY" ]; then
    echo -e "${RED}Error: Could not extract near_signer_public_key${NC}"
    exit 1
fi

echo -e "${GREEN}Signer public key: ${SIGNER_KEY}${NC}"

# Add signer key as access key
echo -e "\n${YELLOW}Adding signer key as access key to ${ACCOUNT_NAME}...${NC}"
echo -e "${GREEN}Executing command:${NC}"
echo "near account add-key ${ACCOUNT_NAME} grant-full-access use-manually-provided-public-key ${SIGNER_KEY} network-config mpc-localnet sign-with-keychain send"

near account add-key "${ACCOUNT_NAME}" grant-full-access use-manually-provided-public-key "${SIGNER_KEY}" network-config mpc-localnet sign-with-keychain send

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully added signer key${NC}"
else
    echo -e "${RED}✗ Failed to add signer key${NC}"
    exit 1
fi

# Extract and add responder keys
echo -e "\n${YELLOW}Processing responder keys...${NC}"
RESPONDER_KEYS=$(echo "$PUBLIC_DATA" | jq -r '.near_responder_public_keys[]' 2>/dev/null)

if [ -z "$RESPONDER_KEYS" ]; then
    echo -e "${YELLOW}No responder keys found or array is empty.${NC}"
else
    # Count number of responder keys
    KEY_COUNT=$(echo "$PUBLIC_DATA" | jq '.near_responder_public_keys | length')
    echo -e "${GREEN}Found ${KEY_COUNT} responder key(s)${NC}"
    
    # Process each responder key
    INDEX=1
    echo "$RESPONDER_KEYS" | while IFS= read -r RESPONDER_KEY; do
        if [ -n "$RESPONDER_KEY" ] && [ "$RESPONDER_KEY" != "null" ]; then
            echo -e "\n${YELLOW}Adding responder key ${INDEX}/${KEY_COUNT}: ${RESPONDER_KEY}${NC}"
            echo -e "${GREEN}Executing command:${NC}"
            echo "near account add-key ${ACCOUNT_NAME} grant-full-access use-manually-provided-public-key ${RESPONDER_KEY} network-config mpc-localnet sign-with-keychain send"
            
            near account add-key "${ACCOUNT_NAME}" grant-full-access use-manually-provided-public-key "${RESPONDER_KEY}" network-config mpc-localnet sign-with-keychain send
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓ Successfully added responder key ${INDEX}${NC}"
            else
                echo -e "${RED}✗ Failed to add responder key ${INDEX}${NC}"
            fi
            ((INDEX++))
        fi
    done
fi

echo -e "\n${GREEN}Key assignment process completed for ${ACCOUNT_NAME}!${NC}"
echo -e "${YELLOW}Summary:${NC}"
echo -e "  Account: ${ACCOUNT_NAME}"
echo -e "  Port: ${PORT}"
echo -e "  Signer Key: ${SIGNER_KEY}"