# Run a Single MPC Node on Localnet (dstack CVM)

This script:
- Creates/reuses one NEAR account on localnet
- Deploys one MPC node into dstack CVM   (node is not guaranteed to be fully functional) 
- Fetches `/public_data` and saves it to JSON

It is used to generate real attestation data for testing only:
See [UPDATING_LAUNCHER.md](../../../tee_launcher/UPDATING_LAUNCHER.md)

## Prerequisites
- Local NEAR network running: `NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run`
- `mpc-localnet` configured in `near` CLI
- dstack running (`http://127.0.0.1:10000`)
- Tools: `near`, `jq`, `curl`, `envsubst`, `docker`

## Setup variables

### Required
```bash
# dstack base path (the folder containing vmm or vmm-data folder)
export BASE_PATH=/path/to/dstack
# external machine IP (you can use:
#   ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1   | grep -Ev '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)'
export MACHINE_IP=<host-ip-reachable-from-CVM>
# the mpc docker image tag. 
# 1. make sure it is available on docker hub.
# 2. make sure that DEFAULT_IMAGE_DIGEST=sha256:<hash> in mpc/tee_launcher/launcher_docker_compose.yaml corresponds to that tag, by calling 
#   `docker pull nearone/mpc-node:$MPC_IMAGE_TAGS` and then 
#   `docker inspect --format='{{.Id}}' nearone/mpc-node:$MPC_IMAGE_TAGS`
export MPC_IMAGE_TAGS=3.3.0
```

### dstack port
If dstack VMM is not on port 10000:
```bash
export VMM_RPC=http://127.0.0.1:<port>
```

### Optional
If you want to use specific NEAR accounts name instead of defaults:
```bash
export NODE_ACCOUNT=frodo.test.near
export CONTRACT_ACCOUNT=mpc-contract.test.near
```

## Run
From the MPC repo root:
```bash
bash ./localnet/tee/scripts/single-node.sh
```

## Output
- The script prints the work directory and all assigned ports at startup
- Public endpoint: `http://<MACHINE_IP>:<PUBLIC_DATA_PORT>/public_data`
- Saved JSON: `<WORKDIR>/public_data.json` (path printed by the script)

## Cleanup
To remove the CVM after you're done:
```bash
BASE_PATH=/path/to/dstack bash ./localnet/tee/scripts/single-node.sh --cleanup <WORKDIR>
```
The exact command is printed at the end of a successful run.
