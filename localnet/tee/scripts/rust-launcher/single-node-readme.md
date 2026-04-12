# Run a Single MPC Node on Localnet (Rust Launcher)

This script:

- Creates/reuses one NEAR account on localnet
- Deploys one MPC node into a dstack CVM using the **Rust launcher**
- Fetches `/public_data` and saves it to JSON

It is used to generate real attestation data for updating test assets.
See [crates/test-utils/assets/README.md](../../../../crates/test-utils/assets/README.md)

## Prerequisites

- Local NEAR network running: `NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run`
- `mpc-localnet` configured in `near` CLI
- dstack running (`http://127.0.0.1:10000`)
- Tools: `near`, `jq`, `curl`, `envsubst`, `docker`

## Required Variables

```bash
# dstack base path — the folder containing vmm/src/vmm-cli.py
export BASE_PATH=/path/to/meta-dstack/dstack

# External machine IP reachable from the CVM
export MACHINE_IP=<host-ip>

# MPC node image tag (must support TOML config / start-with-config-file)
# Verify DEFAULT_IMAGE_DIGEST in deployment/cvm-deployment/launcher_docker_compose.yaml
# matches this tag's manifest digest. You can look it up on Docker Hub or
# in the registry's tag listing — no need for `docker inspect`.
export MPC_IMAGE_TAGS=main-9515e18
```

## Optional Variables

```bash
# dstack VMM port (default: http://127.0.0.1:10000)
export VMM_RPC=http://127.0.0.1:<port>

# Guest OS image (default: dstack-dev-0.5.8)
export OS_IMAGE=dstack-0.5.8

# Custom NEAR accounts
export NODE_ACCOUNT=frodo.test.near
export CONTRACT_ACCOUNT=mpc-contract.test.near
```

## Run

From the MPC repo root:

```bash
bash localnet/tee/scripts/rust-launcher/single-node.sh
```

## Output

- Work directory and assigned ports printed at startup
- Public endpoint: `http://<MACHINE_IP>:<PUBLIC_DATA_PORT>/public_data`
- Saved JSON: `<WORKDIR>/public_data.json` (path printed by the script)

## Updating Test Assets

After collecting `public_data.json`, update test assets:

```bash
cp <WORKDIR>/public_data.json crates/test-utils/assets/public_data.json
cd crates/test-utils/assets && bash ./create-assets.sh public_data.json .
cp crates/test-utils/assets/tcb_info.json crates/attestation/assets/tcb_info.json
```

Then update `VALID_ATTESTATION_TIMESTAMP` in `crates/test-utils/src/attestation.rs`.

## Cleanup

To remove the CVM after you're done:

```bash
BASE_PATH=/path/to/dstack bash localnet/tee/scripts/rust-launcher/single-node.sh --cleanup <WORKDIR>
```

The exact command is printed at the end of a successful run.
