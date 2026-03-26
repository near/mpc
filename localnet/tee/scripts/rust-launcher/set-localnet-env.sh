#!/usr/bin/env bash
# Source this file before running deploy-tee-localnet.sh:
#   source localnet/tee/scripts/set-localnet-env.sh

export HOST_PROFILE=alice
export MODE=localnet
export MPC_NETWORK_BASE_NAME=mpc-local
export REUSE_NETWORK_NAME=mpc-local
export N=2

export MACHINE_IP=51.68.219.1
export BASE_PATH=/mnt/data/barak/dstack_latest/meta-dstack/dstack
export VMM_RPC=http://127.0.0.1:10000

export MPC_IMAGE_NAME=nearone/mpc-node
export MPC_IMAGE_TAGS=main-9515e18
export MPC_REGISTRY=registry.hub.docker.com

export NEAR_NETWORK_CONFIG=mpc-localnet
export NEAR_RPC_URL=http://127.0.0.1:3030
export ACCOUNT_SUFFIX=.test.near

export FUNDER_ACCOUNT=test.near
export FUNDER_PRIVATE_KEY="$(jq -r '.secret_key' ~/.near/mpc-localnet/validator_key.json)"

export MAX_NODES_TO_FUND=2

export NEAR_TX_SLEEP_SEC=1
export NEAR_RETRY_SLEEP_SEC=2

export RESUME=0
