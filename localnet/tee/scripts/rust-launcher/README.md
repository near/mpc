# Launcher Localnet Scripts

Scripts for deploying and testing MPC nodes with the launcher on localnet (TDX CVMs via dstack).

> **The cluster deploy + test scripts moved to `near/mpc-private`**
> (`tools/tee-cluster/`): `deploy-tee-cluster.sh`, `set-*-env.sh`,
> `create-and-sweep-to-treasury.sh`, `test-migration.sh`,
> `test-verify-and-upgrade.sh`, `test-hash-override.sh`, and their how-to docs.
> They run against a local mpc checkout via `MPC_REPO_ROOT`. See the internal
> `tools/tee-cluster/README.md`.
>
> This directory keeps the single-node **test-asset generation** tooling and the
> shared helpers/templates those moved scripts still reference from here.

## Prerequisites

- Local NEAR network running (`mpc-localnet`)
- dstack VMM running (default: `http://127.0.0.1:10000`)
- OS image: `dstack-dev-0.5.8`
- MPC node image must support TOML config (`start-with-config-file`), e.g. `main-9515e18` or later
- Tools: `near`, `jq`, `curl`, `envsubst`, `docker`

## Scripts (in this directory)

| Script | Description |
|--------|-------------|
| [`single-node.sh`](single-node-readme.md) | Deploy a single CVM to collect `/public_data` for test asset generation. |
| `node.conf.localnet.toml.tpl` / `node.conf.testnet.toml.tpl` | TOML config templates rendered via `envsubst` (one per `MODE`). Referenced by `single-node.sh` and by the moved cluster scripts (via `MPC_REPO_ROOT`). |
| `common.sh` | **Sourced, not executed.** Shared helpers: coloured logging (`log`/`warn`/`err`/`pass`/`fatal`), `HOST_PROFILE` → IP layout, `ip_for_i`, `ports_to_toml`, `$CLI` for the dstack vmm-cli, and `near_call_ro`/`near_call_tx` + `extract_json_ro`/`extract_json_tx` wrappers. Used by `single-node.sh` and the moved cluster/test scripts. |

The node env template `../node.env.tpl` also lives here (one level up) and is shared the same way.

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
