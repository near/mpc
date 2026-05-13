# How to Run: `deploy-tee-cluster.sh` (Rust Launcher)

This document explains how to run **`deploy-tee-cluster.sh`** to deploy and
operate an N-node MPC cluster inside TDX-backed CVMs on a single server.
The script supports both **localnet** (default) and **testnet** modes via
the `MODE` env var. Supersedes the deleted
`deployment/testnet/scripts/scale-testnet-tee.sh` (PR #2952).

## Quick Start — Localnet

```bash
# 1. Start localnet
rm -rf ~/.near/mpc-localnet
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
cp -rf deployment/localnet/. ~/.near/mpc-localnet
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run &

# 2. Set environment variables
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh

# 3. Deploy
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
```

## Quick Start — Testnet

```bash
# 1. Pick or fund a top-level testnet account that pays for everything.
#    Faucet caps at 10 NEAR/account; if your FUNDER is short, run the
#    `create-and-sweep-to-treasury.sh` helper a few times (see "Funding
#    FUNDER_ACCOUNT" section below).
export FUNDER_ACCOUNT=<your-top-level-funded>.testnet

# 2. Required env vars
export MPC_NETWORK_BASE_NAME=<short-prefix>     # e.g. dss-test
export N=2                                      # number of nodes
export MAX_NODES_TO_FUND=$N                     # avoid over-provisioning ROOT
export BASE_PATH=/path/to/meta-dstack/dstack
export MPC_MANIFEST_DIGEST=sha256:<digest>      # mpc-node image manifest to vote in
export MODE=testnet
export NEAR_NETWORK_CONFIG=testnet
export HOST_PROFILE=alice                       # alice|bob (controls IP_PREFIX)
export ROOT_INITIAL_BALANCE="20 NEAR"           # contract (16) + N nodes (1 ea) + buffer
export NO_PAUSE=1                               # auto-confirm phase prompts

# 3. Deploy
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
```

The script auto-derives `ACCOUNT_SUFFIX=".${FUNDER_ACCOUNT}"` so the
generated ROOT account is correctly a subaccount of FUNDER — NEAR's
permission model requires this for `create-account fund-myself`.

---

## Funding `FUNDER_ACCOUNT` (testnet)

The default `ROOT_INITIAL_BALANCE=20 NEAR` (sized for N≤3; raise for
larger N or pre-funded scale-up) means `FUNDER_ACCOUNT` needs at least
that many *spendable* NEAR. "Spendable" = `amount - storage_minimum`;
if the funder account has a deployed contract, ~1 NEAR per 100 KB is
locked for storage and unavailable to send.

To check spendable balance:

```bash
near account view-account-summary $FUNDER_ACCOUNT \
  network-config testnet now \
  | grep -E "Native account balance|Storage used"
```

If short, sponsor a fresh faucet account and sweep it to FUNDER. The
testnet faucet caps at ~10 NEAR per account, so this often needs to
run more than once:

```bash
# Run 2–3 times for ~20–30 NEAR top-up
bash localnet/tee/scripts/rust-launcher/create-and-sweep-to-treasury.sh \
  $FUNDER_ACCOUNT
```

Each run creates a fresh `fundmyself-<6hex>.testnet`, waits for it to
land on chain, and sweeps its balance (minus 0.02 NEAR for storage)
into FUNDER. It then leaves the empty account credentials in
`~/.near-credentials/testnet/`.

Alternatives if the faucet is rate-limiting you:

- Send NEAR from another account you control:
  ```bash
  near tokens <source>.testnet send-near $FUNDER_ACCOUNT '<amount> NEAR' \
    network-config testnet sign-with-keychain send
  ```
- Use a non-default RPC (`NEAR_RPC_URL=https://test.rpc.fastnear.com`)
  if the default RPC is rate-limiting your `view-account-summary` /
  account-creation calls.

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

### Common (both modes)

- NEAR CLI installed (`near-cli-rs`)
- dstack VMM running (default: `http://127.0.0.1:10000`)
- OS image available (default: `dstack-dev-0.5.8`)
- MPC repository cloned
- Script path: `localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh`
- **Resource budget**: each CVM takes 8 vCPUs, 64 GB RAM, 500 GB disk
  (per `deployment/cvm-deployment/deploy-launcher.sh`). Practical max
  cluster size on the alice/bob hardware is **~5 nodes per server**;
  beyond that you'll exhaust host resources. The script doesn't
  orchestrate multi-host deploys.
- **Launcher image**: `deployment/cvm-deployment/launcher_docker_compose.yaml`
  must reference a launcher image **built after PR #3026** (the one
  that renamed the user-config TOML field `image` → `image_reference`).
  An older launcher image will crash inside the CVM with
  `TOML parse error: missing field 'image'`. Update the launcher
  digest in that file before running this script if the operator
  hasn't done so already — it's tracked separately from this PR.

### Localnet-only

- Local NEAR network running (`mpc-localnet`):

  ```bash
  rm -rf ~/.near/mpc-localnet
  neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
  cp -rf deployment/localnet/. ~/.near/mpc-localnet
  NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run
  ```
- Validator key at `~/.near/mpc-localnet/validator_key.json`

### Testnet-only

- A funded **top-level** testnet account (≥ 20 NEAR for default
  `ROOT_INITIAL_BALANCE`, raise for larger N). The faucet caps at
  10 NEAR/account; consolidate from multiple faucet runs using
  [`create-and-sweep-to-treasury.sh`](create-and-sweep-to-treasury.sh)
  in this directory.
- Account credentials in `~/.near-credentials/testnet/`
- The static IPs picked by `HOST_PROFILE` (alice → `51.68.219.<1+i>`,
  bob → `5.196.36.<113+i>`) must be configured on the host. Override
  per-node with `NODE_IP_OVERRIDES="0=… 1=…"`.

---

## Environment Variables

The easiest way is to source the per-mode convenience script:

```bash
# Localnet
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh

# Testnet
source localnet/tee/scripts/rust-launcher/set-testnet-env.sh
```

Edit the values (especially `FUNDER_ACCOUNT`, `MPC_MANIFEST_DIGEST`,
`MPC_NETWORK_BASE_NAME`) before sourcing.

### Required (localnet)

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

### Required (testnet)

See the **Quick Start — Testnet** section above for the full set. Key
differences from localnet:

- `MODE=testnet`
- `NEAR_NETWORK_CONFIG=testnet` (`NEAR_RPC_URL` auto-derives to
  `https://rpc.testnet.near.org`; override with `NEAR_RPC_URL=https://test.rpc.fastnear.com`
  for a more reliable RPC if you hit rate limits)
- `HOST_PROFILE=alice|bob` (chooses IP_PREFIX)
- `FUNDER_ACCOUNT` is required (faucet path is rate-limited and not
  recommended) — see Prerequisites
- `ACCOUNT_SUFFIX` is auto-derived from `FUNDER_ACCOUNT`; override only
  if you specifically want a different ROOT placement

### Optional Control Variables

```bash
export START_FROM_PHASE=render|deploy|init_args|near_keys|near_init|near_vote_hash|near_vote_launcher_hash|near_vote_measurement|near_vote_domain
export STOP_AFTER_PHASE=<phase>
export RESUME=1
export FORCE_REDEPLOY=1
export FORCE_RECOLLECT=1
export FORCE_REINIT_ARGS=1
```

### DSS state sync (testnet only)

For `MODE=testnet`, the script enables DSS-first state sync by default
(localnet disables state sync entirely, so these have no effect there):

- `TIER3_PUBLIC_ADDR` is auto-derived per-node as `${ip}:${STATE_SYNC_PORT}` —
  not user-overridable.
- `EXTERNAL_STORAGE_FALLBACK_THRESHOLD` defaults to `100`. Override to
  change behavior:

```bash
# Bucket-only (DSS never runs):
export EXTERNAL_STORAGE_FALLBACK_THRESHOLD=0

# More P2P retries before falling back to the bucket:
export EXTERNAL_STORAGE_FALLBACK_THRESHOLD=1000
```

---

## Running the Script (Fresh Run)

```bash
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh
export RESUME=0
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
```

---

## Common Resume Commands

### Re-render configs only
```bash
export START_FROM_PHASE=render STOP_AFTER_PHASE=render RESUME=0
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
```

### Resume from deploy
```bash
export START_FROM_PHASE=deploy RESUME=1
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
```

### Resume from contract initialization
```bash
export START_FROM_PHASE=init_args RESUME=1
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
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

The exact account names and `network-config` differ by mode. Substitute
in:

- **Localnet**: `<contract>=mpc.mpc-local.test.near`,
  `<funder>=mpc-local.test.near`, `network-config mpc-localnet`
- **Testnet**: `<contract>=mpc.<network>.${FUNDER_ACCOUNT}` (e.g.
  `mpc.dss-test-3282.barak-test-31b3_mpc.testnet`),
  `<funder>=$FUNDER_ACCOUNT`, `network-config testnet`. The script
  prints the exact resolved names in its "Resolved naming and IPs"
  block at start.

### Check contract state
```bash
near contract call-function as-read-only <contract> state \
  json-args {} network-config <network-config> now
```

State should progress: `Initializing` → `Running` once nodes finish
key generation. (On testnet, expect ~20–60 min after deploy for the
nodes to state-sync and complete keygen.)

### Get TEE accounts
```bash
near contract call-function as-read-only <contract> get_tee_accounts \
  json-args {} network-config <network-config> now
```

### Check attestation (should be Dstack, not Mock)
```bash
near contract call-function as-read-only <contract> get_attestation \
  json-args '{"tls_public_key": "ed25519:<TLS_KEY>"}' \
  network-config <network-config> now
```

### Generate sign request
```bash
near contract call-function as-transaction <contract> sign \
  file-args docs/localnet/args/sign_ecdsa.json \
  prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
  sign-as node0.<network>.${FUNDER_ACCOUNT_OR_TEST_NEAR} \
  network-config <network-config> sign-with-keychain send
```

### Automated verification (localnet only)

```bash
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh verify
```

(`test-verify-and-upgrade.sh` is hardcoded for localnet; testnet
verification uses the per-step `near` commands above.)

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
- `NEAR_BOOT_NODES` points the CVM at `10.0.2.2:24566` — the QEMU slirp gateway
  that routes to the host's loopback. This works regardless of whether `neard`
  binds to `0.0.0.0` or `127.0.0.1`, so the same config works across localnet
  variants. `MACHINE_IP` is still used elsewhere (public-data endpoints,
  telemetry) and should remain set to the host's external IP.
