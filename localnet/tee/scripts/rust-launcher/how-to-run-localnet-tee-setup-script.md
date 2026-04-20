# How to Run: Localnet MPC TEE Deployment Script (Rust Launcher)

This document explains how to run the **localnet MPC TEE scale script** to deploy and operate multiple MPC nodes inside TDX-backed CVMs on a **single server**, assuming a local NEAR network (localnet) is already running.

## Quick Start

```bash
# 1. Start localnet
rm -rf ~/.near/mpc-localnet
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
cp -rf deployment/localnet/. ~/.near/mpc-localnet
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run &

# 2. Set environment variables
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh

# 3. Deploy
bash localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh
```

---

## High-Level Description

The script automates the end-to-end setup of an MPC network on localnet:

- Renders per-node TOML configuration and environment files
- Deploys one TDX CVM per MPC node using dstack
- Starts MPC nodes inside CVMs (via the Rust launcher)
- Collects node public keys via `/public_data`
- Generates `init_args.json` for the MPC contract
- Adds keys to node NEAR accounts
- Initializes the MPC contract
- Votes for the MPC Docker image hash
- Votes for the launcher image hash
- Votes for OS measurements (from compiled-in `tcb_info.json` files)
- Votes to add signing domains (all nodes vote)
- Leaves the network ready to process `sign` requests

The script is **resume-safe** and can continue from any phase.

---

## Prerequisites

### NEAR / Localnet

- Local NEAR network running (`mpc-localnet`)

```bash
rm -rf ~/.near/mpc-localnet  # clean up any existing localnet
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
cp -rf deployment/localnet/. ~/.near/mpc-localnet
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run
```

- NEAR CLI installed
- Validator key available at `~/.near/mpc-localnet/validator_key.json`

### dstack

- dstack VMM running (default: `http://127.0.0.1:10000`)
- OS image available (default: `dstack-dev-0.5.8`)

### Repository

- MPC repository cloned
- Script path: `localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh`

---

## Environment Variables

The easiest way is to source the convenience script:

```bash
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh
```

Review and adjust the values in that file before sourcing. Key variables:

### Required

```bash
# Machine / dstack
export MACHINE_IP=<EXTERNAL_SERVER_IP>
export BASE_PATH=/path/to/meta-dstack/dstack  # must contain vmm/src/vmm-cli.py
export VMM_RPC=http://127.0.0.1:10000

# MPC node image name (repository)
export MPC_IMAGE=nearone/mpc-node
# For non-Docker Hub registries, include the registry prefix:
#   export MPC_IMAGE=ghcr.io/nearone/mpc-node

# Manifest digest of the MPC node image (for DEFAULT_IMAGE_DIGEST and voting)
# Get with: docker pull nearone/mpc-node:<tag> 2>&1 | grep Digest
export MPC_MANIFEST_DIGEST=sha256:5d1e604dcf3197f8b465c854f8073eaa89b9733f646248d59f86a15b81110ef5

# NEAR localnet
export NEAR_NETWORK_CONFIG=mpc-localnet
export NEAR_RPC_URL=http://127.0.0.1:3030
export ACCOUNT_SUFFIX=.test.near
export FUNDER_ACCOUNT=test.near
export FUNDER_PRIVATE_KEY=$(jq -r '.secret_key' ~/.near/mpc-localnet/validator_key.json)

# Network
export MODE=localnet
export MPC_NETWORK_BASE_NAME=mpc-local
export REUSE_NETWORK_NAME=mpc-local
export N=2
export MAX_NODES_TO_FUND=2
```

### Optional Control Variables

```bash
export START_FROM_PHASE=render|deploy|init_args|near_keys|near_init|near_vote_hash|near_vote_launcher_hash|near_vote_measurement|near_vote_domain
export STOP_AFTER_PHASE=<phase>
export RESUME=1
export FORCE_REDEPLOY=1
export FORCE_RECOLLECT=1
export FORCE_REINIT_ARGS=1
```

---

## Running the Script (Fresh Run)

```bash
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh
export RESUME=0
bash localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh
```

---

## Common Resume Commands

### Re-render configs only
```bash
export START_FROM_PHASE=render STOP_AFTER_PHASE=render RESUME=0
bash localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh
```

### Resume from deploy
```bash
export START_FROM_PHASE=deploy RESUME=1
bash localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh
```

### Resume from contract initialization
```bash
export START_FROM_PHASE=init_args RESUME=1
bash localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh
```

---

## Output Artifacts

All generated files are stored under:

```
/tmp/$USER/mpc_testnet_scale/<network-name>/
```

Important artifacts:
- `node{i}.toml` — TOML config for the Rust launcher
- `node{i}.env` — environment file for dstack deployment
- `keys.json` — collected node public keys
- `init_args.json` — contract initialization arguments

---

## Verification

After the script completes successfully:

### Check contract state
```bash
near contract call-function as-read-only mpc.mpc-local.test.near state \
  json-args {} network-config mpc-localnet now
```

### Get TEE accounts
```bash
near contract call-function as-transaction mpc.mpc-local.test.near get_tee_accounts \
  json-args {} prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as mpc-local.test.near network-config mpc-localnet sign-with-keychain send
```

### Check attestation (should be Dstack, not Mock)
```bash
near contract call-function as-read-only mpc.mpc-local.test.near get_attestation \
  json-args '{"tls_public_key": "ed25519:<TLS_KEY>"}' \
  network-config mpc-localnet now
```

### Generate sign request
```bash
near contract call-function as-transaction mpc.mpc-local.test.near sign \
  file-args docs/localnet/args/sign_ecdsa.json \
  prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
  sign-as node0.mpc-local.test.near network-config mpc-localnet \
  sign-with-keychain send
```

### Automated verification

```bash
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh verify
```

---

## Test Scripts

| Script | Description |
|--------|-------------|
| `test-verify-and-upgrade.sh verify` | Verify cluster: state, TEE accounts, Dstack attestation, ECDSA signature |
| `test-verify-and-upgrade.sh upgrade <tag>` | Rolling upgrade: vote new hash, restart CVMs, verify |
| `test-hash-override.sh override <hash> <tag>` | Test `mpc_hash_override` forces specific approved hash |
| `test-hash-override.sh override-reject` | Test launcher rejects unapproved override hash |

---

## Notes

- All nodes vote for **add-domain**
- Node-to-node ports are per-node (`13001+i`)
- Telemetry uses port `18082` with per-node IPs
- Script is designed for iterative debugging and safe restarts
- The launcher uses TOML config
- MPC node image must support `start-with-config-file` (commit `9515e18` or later)
