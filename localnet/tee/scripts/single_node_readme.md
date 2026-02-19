# Run a Single MPC Node on Localnet (dstack CVM)

This script:
- Creates/reuses one NEAR account on localnet
- Deploys one MPC node into dstack CVM   (node is not garentied to be fully functional) 
- Fetches `/public_data` and saves it to JSON

It is used to generate real attestation data for testing only:
See [UPDATING_LAUNCHER.md](../../../tee_launcher/UPDATING_LAUNCHER.md)

## Prerequisites
- Local NEAR network running: `NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run`
- `mpc-localnet` configured in `near` CLI
- dstack running (`http://127.0.0.1:10000`)
- Tools: `near`, `jq`, `curl`, `envsubst`, `docker`

## Setup
```bash
export BASE_PATH=/path/to/dstack
export MACHINE_IP=<host-ip-reachable-from-CVM>
export MPC_IMAGE_TAGS=3.3.0
```

## dstack port
If dstack VMM is not on port 10000:
```bash
export VMM_RPC=http://127.0.0.1:<port>
```


# Optional
export NODE_ACCOUNT=frodo.test.near
export CONTRACT_ACCOUNT=mpc-contract.test.near
```

## Run
From the MPC repo root:
```bash
bash ./localnet/tee/scripts/single_node.sh
```

## Output
- Public endpoint: `http://<MACHINE_IP>:18082/public_data`
- Saved JSON: `/tmp/<user>/mpc_localnet_one_node/public_data.json`
