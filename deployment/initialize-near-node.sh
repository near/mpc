#!/bin/bash
set -x -e

# This is for development: clear the whole data directory and start over.
if [ "$RESET_DATA" = "1" ]; then
    echo "Resetting data"
    rm -rf /data/*
fi

echo Initializing Near node using chain ID ${CHAIN_ID:?"CHAIN_ID is required"}, tracking contract ${CONTRACT:?"CONTRACT is required"}

HOME_DIR=/data

# Initialize the node from config and genesis.
neard --home ${HOME_DIR} init --chain-id=$CHAIN_ID --download-genesis --download-config

# Fill in configs that we need to tweak for the mpc setup.
python3 << EOF
import json;
config = json.load(open('/data/config.json'))

# boot nodes must be filled in or else the node will not have any peers.
config['network']['boot_nodes'] = "${BOOT_NODES}"

# Track whichever shard the contract account is on.
config['tracked_shards'] = []
config['tracked_accounts'] = ["$CONTRACT"]
json.dump(config, open('/data/config.json', 'w'), indent=2)
EOF

# Run the node. The node will catch up via epoch sync, header sync, state sync, and finally block sync.
# the node is ready when the logs start printing block hashes in the status line.
neard --home ${HOME_DIR} run
