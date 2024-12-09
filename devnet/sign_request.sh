#!/bin/bash
SOURCE="nearone-robin.testnet"
SUFFIX="-test3"

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

near call "signer$SUFFIX.$SOURCE" --use-account $SOURCE sign "$REQUEST" --deposit-yocto 1 --gas 60000000000000