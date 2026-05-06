# Launcher Localnet Scripts

Scripts for deploying and testing MPC nodes with the launcher on localnet (TDX CVMs via dstack).

## Prerequisites

- Local NEAR network running (`mpc-localnet`)
- dstack VMM running (default: `http://127.0.0.1:10000`)
- OS image: `dstack-dev-0.5.8`
- MPC node image must support TOML config (`start-with-config-file`), e.g. `main-9515e18` or later
- Tools: `near`, `jq`, `curl`, `envsubst`, `docker`

## Scripts

| Script | Description |
|--------|-------------|
| [`deploy-tee-cluster.sh`](how-to-run-deploy-tee-cluster.md) | Deploy a 2-node MPC cluster with the Rust launcher. Resume-safe, phase-based. |
| [`single-node.sh`](single-node-readme.md) | Deploy a single CVM to collect `/public_data` for test asset generation. |
| `set-localnet-env.sh` / `set-testnet-env.sh` | Sourceable env-var presets for `deploy-tee-cluster.sh` (one per `MODE`). Review and adjust before use. |
| `node.conf.localnet.toml.tpl` / `node.conf.testnet.toml.tpl` | TOML config templates rendered by the deploy scripts via `envsubst` (one per `MODE`). |
| `test-verify-and-upgrade.sh` | Cluster verification and rolling upgrade test (localnet). |
| `test-hash-override.sh` | Test `mpc_hash_override` TOML config parameter (positive and negative cases). |
| `create-and-sweep-to-treasury.sh` | **(testnet only)** Faucet a fresh account and sweep it to a treasury. Useful before a `MODE=testnet` deploy when your `FUNDER_ACCOUNT` is short on NEAR (faucet caps at ~10 NEAR per account). |

## Quick Start

```bash
# 1. Start localnet
rm -rf ~/.near/mpc-localnet
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
cp -rf deployment/localnet/. ~/.near/mpc-localnet
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run &

# 2. Set environment variables (review and adjust first)
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh

# 3. Deploy 2-node cluster
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh

# 4. Verify cluster
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh verify
```

## Test Commands

```bash
# Verify cluster: state, TEE accounts, Dstack attestation, ECDSA signature
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh verify

# Rolling upgrade to a new MPC node image
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh upgrade main-f80f491

# Test hash override (force a specific approved image)
bash localnet/tee/scripts/rust-launcher/test-hash-override.sh override <64-hex-hash> <image-tag>

# Test override rejection (unapproved hash — launcher should exit with error)
bash localnet/tee/scripts/rust-launcher/test-hash-override.sh override-reject
```

## Collecting Test Assets

To regenerate test assets from real TDX attestation:

```bash
# Deploy single node
bash localnet/tee/scripts/rust-launcher/single-node.sh

# Extract assets
cp <WORKDIR>/public_data.json crates/test-utils/assets/public_data.json
cd crates/test-utils/assets && bash ./create-assets.sh public_data.json .
cp crates/test-utils/assets/tcb_info.json crates/attestation/assets/tcb_info.json
# Update VALID_ATTESTATION_TIMESTAMP in crates/test-utils/src/attestation.rs
```

See [single-node-readme.md](single-node-readme.md) for details.
