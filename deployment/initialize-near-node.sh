#!/bin/bash
set -x -e

if [ "$RESET_DATA" = "1" ]; then
    echo "Resetting data"
    rm -rf /data/*
fi

echo Initializing Near node using chain ID ${CHAIN_ID:?"CHAIN_ID is required"}, tracking contract ${CONTRACT:?"CONTRACT is required"}

HOME_DIR=/data

neard --home ${HOME_DIR} init --chain-id=$CHAIN_ID --download-genesis --download-config
python3 << EOF
import json;
config = json.load(open('/data/config.json'))
config['network']['boot_nodes'] = "${BOOT_NODES}"
config['state_sync']['sync']['ExternalStorage']['external_storage_fallback_threshold'] = 0
config['tracked_shards'] = []
config['tracked_accounts'] = ["$CONTRACT"]
json.dump(config, open('/data/config.json', 'w'), indent=2)
EOF
neard --home ${HOME_DIR} run
