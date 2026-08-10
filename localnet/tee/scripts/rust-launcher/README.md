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
# Deploy single node. PRELAUNCH_SCRIPT is what makes the node's signer secret
# key recoverable; see below.
PRELAUNCH_SCRIPT=/path/to/prelaunch.sh bash localnet/tee/scripts/rust-launcher/single-node.sh

# Extract assets
cp <WORKDIR>/public_data.json crates/test-utils/assets/public_data.json
cd crates/test-utils/assets && bash ./create-assets.sh public_data.json .
cp crates/test-utils/assets/tcb_info.json crates/attestation/assets/tcb_info.json
# Update VALID_ATTESTATION_TIMESTAMP in crates/test-utils/src/attestation.rs
# Regenerate the verifier's borsh arg fixture and the expected report:
UPDATE_FIXTURES=1 cargo test -p tee-verifier --test verify_quote verify_quote_args_fixture
cargo test -p tee-verifier --test verify_quote  # update the hardcoded report values it prints
```

### Exporting the node's signer key

Sandbox tests that store a Verified attestation must sign as the fixture node,
because the quote's `report_data` binds the node's account key and the contract
reads that key from the transaction signer. That key is generated inside the
CVM, so it has to be exported during collection or the fixture is unusable for
those tests (this is what issue #3787 was about).

Supplying the key instead of exporting it does not work: the node reuses an
existing `secrets.json` if it finds one, but the launcher's measured compose
mounts only the `mpc-data` volume into the node container, so the host has
nowhere to put it.

`PRELAUNCH_SCRIPT` points at a script baked into the app-compose and run inside
the CVM before the node starts. Notes from making this work:

- The guest is BusyBox: stick to shell built-ins and globs. GNU-only options
  such as `head -1` fail, and there is no `sshd`, no `/root`, and no
  `/usr/local/bin`.
- `/etc` (overlay) and `/dstack/.host-shared` are writable; `/` is not.
- The node writes `secrets.json` only after the hook returns, so the wait must
  run as its own systemd unit. A plain background process is reaped with
  `app-compose.service`'s cgroup.
- Anything echoed to `/dev/console` lands in the host's
  `run/vm/<id>/serial.log`, which is the simplest way to read a value out.

A hook that copies the key to the host-visible shared dir:

```sh
cat > /etc/fixture-exfil.sh <<'EOF'
#!/bin/sh
i=0
while [ "$i" -lt 900 ]; do
  for f in /var/lib/docker/volumes/*/_data/secrets.json; do
    [ -f "$f" ] && { cp "$f" /dstack/.host-shared/fixture-secrets.json; exit 0; }
  done
  i=$((i + 1)); sleep 2
done
EOF
cat > /etc/systemd/system/fixture-exfil.service <<'EOF'
[Unit]
Description=Export the MPC node signer key for test-asset collection
[Service]
Type=oneshot
ExecStart=/bin/sh /etc/fixture-exfil.sh
EOF
systemctl daemon-reload && systemctl start --no-block fixture-exfil.service
```

Then put `near_signer_key` from that file into
`crates/test-utils/assets/near_account_secret_key` (one line, `ed25519:<base58>`)
and check that its public half equals `near_account_public_key.pub`. Only ever do
this for a throwaway localnet node: the key ends up in the repo.

The hook is measured into the app-compose, and production verification rejects any
app-compose carrying a script. Test builds accept this one field via
`attestation/allow-pre-launch-script`, so keep the hook to what the export needs.

See [single-node-readme.md](single-node-readme.md) for details.
