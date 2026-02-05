# How to Run: Localnet MPC TEE Deployment Script

This document explains how to run the **localnet MPC TEE scale script** to deploy and operate multiple MPC nodes inside TDX-backed CVMs on a **single server**, assuming a local NEAR network (localnet) is already running.

---

## High‑Level Description

The script automates the end‑to‑end setup of an MPC network on localnet:

- Renders per‑node configuration and environment files
- Deploys one TDX CVM per MPC node using dstack
- Starts MPC nodes inside CVMs
- Collects node public keys via `/public_data`
- Generates `init_args.json` for the MPC contract
- Adds keys to node NEAR accounts
- Initializes the MPC contract
- Votes for the MPC Docker image hash
- Votes to add signing domains (all nodes vote)
- Leaves the network ready to process `sign` requests

The script is **resume‑safe** and can continue from any phase.

---

## Prerequisites


### NEAR / Localnet
- Local NEAR network running (`mpc-localnet`)

you can do this by running:

```bash
 rm -rf ~/.near/mpc-localnet #clean up any existing localnet
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
cp -rf deployment/localnet/. ~/.near/mpc-localnet
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run
```


- NEAR CLI installed
- Validator key available at:
  ```
  ~/.near/mpc-localnet/validator_key.json
  ```

### Repository
- MPC repository cloned
- Script path:
  ```
localnet/tee/scripts/deploy_tee_localnet.sh
  ```

---

## Environment Variables

### Required / Common Defaults

```bash
# Mode
export MODE=localnet

# Network
export MPC_NETWORK_BASE_NAME=mpc-local
export REUSE_NETWORK_NAME=mpc-local
export N=2

# Machine / ports
export MACHINE_IP=<EXTERNAL_SERVER_IP>
export FUTURE_BASE_PORT=13001
export VMM_RPC=http://127.0.0.1:10000

# dstack / images
export BASE_PATH=/path/to/dstack
export MPC_IMAGE_NAME=nearone/mpc-node
export MPC_IMAGE_TAGS=3.3.0
export MPC_REGISTRY=registry.hub.docker.com

# NEAR localnet
export NEAR_NETWORK_CONFIG=mpc-localnet
export NEAR_RPC_URL=http://127.0.0.1:3030
export ACCOUNT_SUFFIX=.test.near

# Funding (localnet validator)
export FUNDER_ACCOUNT=test.near
export FUNDER_PRIVATE_KEY=$(jq -r '.secret_key' ~/.near/mpc-localnet/validator_key.json)
```

### Optional Control Variables

```bash
export START_FROM_PHASE=render|deploy|init_args|near_keys|near_init|near_vote_hash|near_vote_domain
export STOP_AFTER_PHASE=<phase>
export RESUME=1
export FORCE_REDEPLOY=1
export FORCE_RECOLLECT=1
export FORCE_REINIT_ARGS=1
```

---

## Running the Script (Fresh Run)

```bash
unset START_FROM_PHASE STOP_AFTER_PHASE
export MODE=localnet
export RESUME=0

bash localnet/tee/scripts/deploy_tee_localnet.sh
```

---

## Common Resume Commands

### Re‑render configs only
```bash
export START_FROM_PHASE=render
export STOP_AFTER_PHASE=render
export RESUME=0
bash localnet/tee/scripts/deploy_tee_localnet.sh
```

### Resume from deploy
```bash
export START_FROM_PHASE=deploy
export RESUME=1
bash localnet/tee/scripts/deploy_tee_localnet.sh
```

### Resume from contract initialization
```bash
export START_FROM_PHASE=init_args
export RESUME=1
bash localnet/tee/scripts/deploy_tee_localnet.sh
```

---

## Output Artifacts

All generated files are stored under:

```
/tmp/$USER/mpc_testnet_scale/<network-name>/
```

Important artifacts:
- `node{i}.conf`, `node{i}.env`
- `keys.json`
- `init_args.json`

---

## Sending a Sign Request

After the script completes successfully:
get state of the contract:

```bash
near contract call-function as-read-only mpc.mpc-local.test.near state json-args {} network-config mpc-localnet now
```

get tee accounts:
```bash
 near contract call-function as-transaction mpc.mpc-local.test.near get_tee_accounts json-args {} prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as mpc-local.test.near network-config mpc-localnet sign-with-keychain send
```

generate sign request:
```bash
near contract call-function as-transaction    mpc.mpc-local.test.near   sign   file-args docs/localnet/args/sign_ecdsa.json   prepaid-gas '300.0 Tgas'   attached-deposit '100 yoctoNEAR'   sign-as node0.mpc-local.test.near   network-config mpc-localnet   sign-with-keychain   send
```


---

## Notes

- All nodes vote for **add‑domain**
- Node‑to‑node ports are per‑node (`13001+i`)
- Telemetry uses port `18082` with per‑node IPs
- Script is designed for iterative debugging and safe restarts

---


