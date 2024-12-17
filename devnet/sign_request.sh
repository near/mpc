#!/bin/bash
SOURCE="nearone-robin.testnet"
SUFFIX="-test-key-generation0004"

REQUEST=$(cat << EOF
{
    "request": {
        "key_version": 0,
        "path": "m/44'/60'/0'/0/0",
        "payload": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 33]
    }
}
EOF)

near call "signer-6e3c4c3b-e824-4f83-aff8-35efa70e360e.testnet" --use-account signer-6e3c4c3b-e824-4f83-aff8-35efa70e360e.testnet sign "$REQUEST" --deposit-yocto 1 --gas 60000000000000