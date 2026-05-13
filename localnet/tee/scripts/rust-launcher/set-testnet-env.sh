#!/usr/bin/env bash
# Source this file before running deploy-tee-cluster.sh in MODE=testnet:
#   source localnet/tee/scripts/rust-launcher/set-testnet-env.sh
#
# Review and adjust the values below before sourcing — at minimum the ones
# marked "EDIT ME". The rest are reasonable defaults for a 2-node testnet
# deploy on the alice host.

# --- EDIT ME: required for any testnet deploy ---

# Funded top-level testnet account that pays for ROOT topup. Faucet caps at
# ~10 NEAR/account; if your funder is short, run:
#   bash localnet/tee/scripts/rust-launcher/create-and-sweep-to-treasury.sh "$FUNDER_ACCOUNT"
# a few times to consolidate ~30 NEAR onto it.
export FUNDER_ACCOUNT="<your-funder>.testnet"

# Manifest digest of the mpc-node image to deploy and vote in.
# Discover the currently-allowed digest with:
#   ./scripts/fetch-allowed-launcher-hashes.sh --network testnet
# Or compute from a freshly pulled image:
#   docker pull nearone/mpc-node:<tag> 2>&1 | grep Digest
export MPC_MANIFEST_DIGEST="sha256:<digest>"

# Manifest digest of the mpc-launcher image to deploy and vote in.
# Discover the currently-allowed digest with:
#   ./scripts/fetch-allowed-launcher-hashes.sh --network testnet
# Or compute from a freshly pulled image:
#   docker pull nearone/mpc-launcher:<tag> 2>&1 | grep Digest
export LAUNCHER_MANIFEST_DIGEST="sha256:<digest>"

# --- Cluster sizing ---

export MPC_NETWORK_BASE_NAME="<short-prefix>"   # e.g. dss-test
export N=2                                      # practical max per server is ~5 (each CVM: 8 vCPU, 64 GB RAM, 500 GB disk)
export MAX_NODES_TO_FUND=$N                     # matches script default; raise to pre-fund scale-up headroom

# --- Network / chain ---

export MODE=testnet
export NEAR_NETWORK_CONFIG=testnet
# Override if hitting the default RPC's rate limits:
#   export NEAR_RPC_URL=https://test.rpc.fastnear.com

# --- Host / dstack ---

# IP allocation profile: alice=51.68.219.<1+i>, bob=5.196.36.<113+i>.
# For arbitrary IPs, set NODE_IP_OVERRIDES instead:
#   export NODE_IP_OVERRIDES="0=<ip0> 1=<ip1>"
export HOST_PROFILE=alice
export BASE_PATH=/mnt/data/barak/dstack_latest/meta-dstack/dstack
export VMM_RPC=http://127.0.0.1:10000

# --- Funding budgets ---

# 16 NEAR contract storage + N nodes (1 NEAR each) + buffer.
# Sized for N≤3 by default; raise for larger N or when MAX_NODES_TO_FUND>>N.
export ROOT_INITIAL_BALANCE="20 NEAR"
# (CONTRACT_INITIAL_BALANCE and NODE_INITIAL_BALANCE use the script's
# defaults — 16 NEAR contract, 1 NEAR per node.)

# --- Image reference (no tag — manifest digest is voted in separately) ---

export MPC_IMAGE=nearone/mpc-node

# --- Run controls ---

# Auto-confirm phase prompts. Set to 0 if you want to ENTER between phases.
export NO_PAUSE=1

# Slightly more patient retry/backoff than localnet defaults — testnet RPC
# is occasionally slow.
export NEAR_TX_SLEEP_SEC=3
export NEAR_RETRY_SLEEP_SEC=5
