#!/usr/bin/env bash
# Source this file to set all environment variables needed by deploy-tee-localnet.sh
# Usage: source localnet/tee/scripts/localnet-env.sh
#
# Review and adjust the values below before sourcing.

# ---------- Host profile ----------
# alice or bob — determines the IP range used for nodes
export HOST_PROFILE=alice

# ---------- Network ----------
export MODE=localnet
export MPC_NETWORK_BASE_NAME=mpc-local
export REUSE_NETWORK_NAME=mpc-local
export N=2
export MAX_NODES_TO_FUND=2
export ACCOUNT_SUFFIX=.test.near

# ---------- NEAR localnet ----------
export NEAR_NETWORK_CONFIG=mpc-localnet
export NEAR_RPC_URL=http://127.0.0.1:3030
export FUNDER_ACCOUNT=test.near
export FUNDER_PRIVATE_KEY=$(jq -r '.secret_key' ~/.near/mpc-localnet/validator_key.json)

# ---------- Contract account ----------
# Must match what nodes use from the start
export MPC_CONTRACT_ACCOUNT=mpc.mpc-local.test.near

# ---------- Machine / ports ----------
# Set MACHINE_IP to the external IP of this server
export MACHINE_IP="${MACHINE_IP:?Set MACHINE_IP to external server IP (e.g. 51.68.219.1)}"
export VMM_RPC=http://127.0.0.1:10000
export FUTURE_BASE_PORT=13001

# ---------- dstack / MPC images ----------
# BASE_PATH must point to the dstack subdir containing vmm/src/vmm-cli.py
export BASE_PATH="${BASE_PATH:?Set BASE_PATH to dstack dir (e.g. /path/to/meta-dstack/dstack)}"
export MPC_IMAGE_NAME=nearone/mpc-node
export MPC_IMAGE_TAGS=3.7.0
export MPC_REGISTRY=registry.hub.docker.com

# ---------- Execution control ----------
export START_FROM_PHASE=preflight
export RESUME=0
export NO_PAUSE=1
export FORCE_RECOLLECT=1
export FORCE_REINIT_ARGS=1

# ---------- Retry / timing ----------
export NEAR_TX_SLEEP_SEC=1
export NEAR_RETRY_MAX=2
export NEAR_RETRY_SLEEP_SEC=3
export NEAR_RETRY_BACKOFF_MULT=2
export NEAR_CLI_DISABLE_SPINNER=1
