#!/bin/bash
##########################################################################################
# Function to display help
##########################################################################################
set -exo pipefail


show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help           Display this help message"
    echo "  -s, --signer_id      Specify signer account id provided by depoloy.sh script"
}


##########################################################################################
# Variable parsing block
##########################################################################################


# Check if an argument is provided
if [ $# -eq 0 ]; then
    echo "No arguments provided, signer_id is required"
    show_help
    exit 1
fi


while [ ! -z "$1" ]; do
   if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
      show_help; exit 0;
   elif [[ $1 == "-s" ]] || [[ "$1" == "--signer_id" ]]; then
      SIGNER="$2"
      shift
   else
      echo "Incorrect input provided $1"
      show_help; exit 1;
   fi
shift
done


##########################################################################################
# Functions block
##########################################################################################


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

near call dev-contract.near --use-account $SIGNER sign "$REQUEST" --deposit-yocto 1 --gas 60000000000000  --networkId mainnet
# near call v1.signer --use-account $SIGNER sign "$REQUEST" --deposit-yocto 1 --gas 60000000000000  --networkId mainnet
