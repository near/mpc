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

To regenerate test assets from real TDX attestation, from the repo root on the TDX host. Set up the
prerequisites and required variables from [single-node-readme.md](single-node-readme.md) first: a
running localnet in `~/.near/mpc-localnet`, `MACHINE_IP`, and the two image digests.

```bash
export BASE_PATH=/path/to/meta-dstack/dstack
export WORKDIR=/tmp/mpc-fixture-collection

# Reuse the fixture's current image digests unless changing images: steps 6-7 then stay no-ops.
COMPOSE_TEMPLATE="$PWD/localnet/tee/scripts/rust-launcher/export-signer-key-compose.yaml.template" \
  bash localnet/tee/scripts/rust-launcher/single-node.sh

cp "$WORKDIR/public_data.json" crates/test-utils/assets/public_data.json
```

Then follow [the asset regeneration steps](../../../../crates/test-utils/assets/README.md#steps) from
step 3, which own the rest of the procedure.

### Exporting the node's signer key

The node generates its NEAR signer key inside the CVM, and sandbox tests need it to sign as the fixture
node. Handing the node a key instead does not work: the measured compose mounts only `mpc-data`.

[export-signer-key-compose.yaml.template](export-signer-key-compose.yaml.template) is the production
launcher compose plus one service that prints the node's `secrets.json`. Verification only hashes the
compose, never reads its contents, so exporting this way needs nothing relaxed. Read the key from that
service's log, on the agent port `single-node.sh` prints:

```bash
curl -s "http://127.0.0.1:$AGENT_PORT/logs/signer-key-export?text&bare" \
  | grep -o '"near_signer_key":"[^"]*"'
```

Put the value into `crates/test-utils/assets/near_account_secret_key` (one line, `ed25519:<base58>`).
Only ever do this for a throwaway localnet node: the key ends up in the repo.
