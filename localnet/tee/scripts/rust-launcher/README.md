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

To regenerate test assets from real TDX attestation, from the repo root on the TDX host:

```bash
export BASE_PATH=/path/to/meta-dstack/dstack
export WORKDIR=/tmp/mpc-fixture-collection

# PRELAUNCH_SCRIPT is what makes the node's signer secret key recoverable; see below.
PRELAUNCH_SCRIPT=localnet/tee/scripts/rust-launcher/export-signer-key-prelaunch.sh \
  bash localnet/tee/scripts/rust-launcher/single-node.sh

cp "$WORKDIR/public_data.json" crates/test-utils/assets/public_data.json
```

Then follow [the asset regeneration steps](../../../../crates/test-utils/assets/README.md#steps) from
step 3, which own the rest of the procedure.

### Exporting the node's signer key

Sandbox tests that store a Verified attestation must sign as the fixture node: the quote's
`report_data` binds the node's account key, and the contract reads that key from the transaction
signer. The node generates it inside the CVM, so it has to be exported during collection.

Supplying the key instead does not work. The node reuses an existing `secrets.json`, but the
launcher's measured compose mounts only the `mpc-data` volume into the node container, so the host has
nowhere to put one.

[export-signer-key-prelaunch.sh](export-signer-key-prelaunch.sh) is the hook that produced the
committed fixture; `PRELAUNCH_SCRIPT` above bakes it into the app-compose. It waits for the node to
write `secrets.json`, then copies it into the CVM's shared dir and echoes it to the console, so
whichever channel the host exposes is enough. Both live under the vmm's `run_path`:

```bash
RUN_VM="$(dirname "$BASE_PATH")/build/run/vm"    # `run_path` in the vmm config
cat "$RUN_VM"/*/shared/fixture-secrets.json
grep -A3 FIXTURE-SECRETS-BEGIN "$RUN_VM"/*/serial.log   # fallback if the copy failed
```

Put `near_signer_key` from there into `crates/test-utils/assets/near_account_secret_key` (one line,
`ed25519:<base58>`). Only ever do this for a throwaway localnet node: the key ends up in the repo.

The script is a copy of what the committed app-compose carries, which is what ties it to the committed
key. After editing either one, this must stay empty:

```bash
diff <(jq -j '.pre_launch_script' crates/test-utils/assets/app_compose.json) \
    localnet/tee/scripts/rust-launcher/export-signer-key-prelaunch.sh
```

Writing a different hook: the guest is BusyBox, so built-ins and globs only and no `sshd`; `/etc` and
`/dstack/.host-shared` are writable but `/` is not; and the wait needs its own systemd unit, since a
background process is reaped with `app-compose.service`'s cgroup.

Any app-compose carrying a script is rejected by production verification. Test builds accept this one
field via `attestation/allow-pre-launch-script`, so keep the hook minimal.

See [single-node-readme.md](single-node-readme.md) for details.
