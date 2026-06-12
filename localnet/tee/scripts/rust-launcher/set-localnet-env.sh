#!/usr/bin/env bash
# Source this file before running deploy-tee-cluster.sh:
#   source localnet/tee/scripts/rust-launcher/set-localnet-env.sh

export HOST_PROFILE=alice
export MODE=localnet
export MPC_NETWORK_BASE_NAME=mpc-local
export REUSE_NETWORK_NAME=mpc-local
export N=2   # number of nodes; practical max per server is ~5 (8 vCPU + 64 GB + 500 GB per CVM)

export MACHINE_IP=51.68.219.1
export BASE_PATH=/mnt/data/barak/dstack_latest/meta-dstack/dstack
export VMM_RPC=http://127.0.0.1:10000

export MPC_IMAGE=nearone/mpc-node
# Manifest digest of the MPC node image (filled into the launcher compose
# template and voted in as the allowed code hash).
# Get with: docker pull nearone/mpc-node:<tag> 2>&1 | grep Digest
export MPC_MANIFEST_DIGEST=sha256:2d399b135910f1c92696c7675d7e95c02e0da3766b39a1943087757e73386a61

# Manifest digest of the launcher image (filled into the launcher compose
# template and voted in as the allowed launcher hash).
# Get with: docker pull nearone/mpc-launcher:<tag> 2>&1 | grep Digest
export LAUNCHER_MANIFEST_DIGEST=sha256:8940a8169c02df46e9afd7489e8721cc813567088b06720b51d06277aab0420d

export NEAR_NETWORK_CONFIG=mpc-localnet
export NEAR_RPC_URL=http://127.0.0.1:3030
export ACCOUNT_SUFFIX=.test.near

export FUNDER_ACCOUNT=test.near
export FUNDER_PRIVATE_KEY="$(jq -r '.secret_key' ~/.near/mpc-localnet/validator_key.json)"

export MAX_NODES_TO_FUND=2

# Migration test drives a lot of operator txns (add-key x2 for the target,
# register_backup_service, start_node_migration) — 1 NEAR per node runs
# out. Give each node 10 NEAR and the root enough to cover.
export NODE_INITIAL_BALANCE="10 NEAR"
export ROOT_INITIAL_BALANCE="45 NEAR"

export NEAR_TX_SLEEP_SEC=1
export NEAR_RETRY_SLEEP_SEC=2

export RESUME=0
