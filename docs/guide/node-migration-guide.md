# Node Migration Guide

This guide provides step-by-step instructions for node operators to migrate their MPC nodes between different hosts or cloud providers using the backup CLI.

## Overview

Node migration allows you to move your MPC node from one host to another without requiring a full network resharing. This is accomplished using the `backup-cli` tool to securely backup and restore your node's keyshares.

**Changing only your URL?** If your node keeps the same TLS key and you only need to point peers at a new address (e.g. fixing a typo or moving to a new domain), call `update_participant_url` on the contract instead of running a migration. It updates just your registered URL; peers pick it up without a resharing or reconnecting existing sessions.

**Important:** This guide covers the **Soft Launch** migration process. For information about the architecture and future Hard Launch implementation, see [migration-service.md](../archive/design/migration-service.md).

## Environment Variables Setup

Set these variables on the machine where you run `backup-cli` and NEAR CLI, at the beginning of your migration; the code examples below use them.

`backup-cli` also reads most of its flags from a same-named environment variable (`--backup-encryption-key-hex` from `BACKUP_ENCRYPTION_KEY_HEX`; a few are prefixed, e.g. `--home-dir` reads `BACKUP_HOME_DIR` — `backup-cli --help` lists each). This guide relies on that for the encryption key, which should never appear on a command line.

Known up front:

```bash
# Your NEAR account ID that operates the MPC node
export SIGNER_ACCOUNT_ID=your-account.testnet

# The MPC contract account ID
export MPC_CONTRACT_ACCOUNT_ID=v1.signer-prod.testnet

# NEAR network configuration (testnet or mainnet)
export NEAR_NETWORK=testnet

# Where backup-cli keeps its keys and the backed-up keyshares (Step 1)
export BACKUP_HOME_DIR=/path/to/backup/home

# The old and new nodes' hosts (or IPs) — used for the nodes' public-data/debug
# endpoints on port 8080 (Steps 4–7) and by the derived variables below
export OLD_NODE_HOST=node.example.com
export NEW_NODE_HOST=new-node.example.com

# The nodes' migration endpoints, as bare host:port — no http://; the port is each
# node's migration_web_ui port (Steps 4 and 7)
export OLD_NODE_MIGRATION_ADDRESS=$OLD_NODE_HOST:8079
export NEW_NODE_MIGRATION_ADDRESS=$NEW_NODE_HOST:8079

# The new node's public URL to register on the contract — http:// prefix required;
# adjust if peers reach the node under a different name (Step 6)
export NEW_NODE_URL=http://$NEW_NODE_HOST:80

# A NEAR RPC provider's endpoint, not your MPC node — only needed for the optional
# continuous backup (Step 4); an api key goes in the query string
export BACKUP_RPC_URL=https://rpc.$NEAR_NETWORK.fastnear.com
```

One more variable lives on the node host rather than this machine:

```bash
# The node's home directory, from the node's .env — commonly /data inside the container (Step 3)
export MPC_HOME_DIR=/data
```

The remaining variables are filled in as you go — each is obtained in the step shown:

- `BACKUP_ENCRYPTION_KEY_HEX` — the shared transport encryption key, 64 hex characters (Step 3)
- `OLD_NODE_P2P_KEY` — the old node's P2P (TLS) public key (Step 4)
- `OLD_NODE_SIGNER_PUBLIC_KEY` — the old node's NEAR signer public key, captured while the old node is still up (Step 4) and revoked in Step 9
- `NEW_NODE_P2P_KEY` — the new node's P2P (TLS) public key (Step 5)
- `NEW_NODE_SIGNER_PUBLIC_KEY` — the new node's NEAR signer public key (Step 5)

**Note:** Adjust these values based on your specific setup. For mainnet deployments, use `mainnet` for `NEAR_NETWORK` and `v1.signer` for `MPC_CONTRACT_ACCOUNT_ID`.

## Prerequisites

Before starting a migration, ensure you have:

1. **An active MPC node** that is a current participant in the network
2. **A new host/machine** ready to run the migrated node
3. **The backup-cli tool** installed on a secure machine (can be your local machine or a dedicated backup server)
4. **NEAR CLI** installed for contract interactions
5. **Access to both nodes** (old and new) during the migration process
6. **An available attestation grant** for your node account — the new node's attestation consumes one (see below)

### Prepay the New Node's Attestation Storage

During a migration your account holds two attestations — the old node's and the new node's — and each stored attestation consumes one prepaid **grant**. The old node's grant stays occupied until its attestation expires and is swept — stopping the old node does not free it — so the new node needs an available grant of its own.

Do this before you start the migration. Check whether a grant is available:

```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  available_attestation_grants \
  json-args "{\"account_id\":\"$SIGNER_ACCOUNT_ID\"}" \
  network-config $NEAR_NETWORK \
  now
```

If it returns `0`, prepay one grant. The fee is a votable contract parameter (currently 20 milliNEAR = 0.02 NEAR per grant) and the attached deposit must equal fee × grants exactly. Read the current fee:

```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  config \
  json-args {} \
  network-config $NEAR_NETWORK \
  now | jq .attestation_storage_fee_millinear
```

See [Prepay Your Node's Attestation Storage](https://github.com/near/mpc/blob/main/docs/guide/running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#prepay-your-nodes-attestation-storage) in the operator guide for the full details, then prepay:

```bash
# attached-deposit must equal current fee × grants exactly — check the fee before running
near contract call-function as-transaction \
  $MPC_CONTRACT_ACCOUNT_ID \
  prepay_attestation_storage \
  json-args "{\"account_id\":\"$SIGNER_ACCOUNT_ID\",\"grants\":1}" \
  prepaid-gas '30.0 Tgas' \
  attached-deposit '0.02 NEAR' \
  sign-as $SIGNER_ACCOUNT_ID \
  network-config $NEAR_NETWORK \
  sign-with-keychain \
  send
```

## Step 1: Setup the Backup CLI

First, you'll need to set up the backup CLI tool and generate keys for the backup service.

### Install backup-cli

Install the backup-cli tool using cargo (run from the repository root):

```bash
cargo install --path crates/backup-cli --locked
```

This installs the `backup-cli` binary to your cargo bin directory (typically `~/.cargo/bin`), which should be in your `PATH`.

### Generate Backup Service Keys

Create the backup home directory (`$BACKUP_HOME_DIR` from [Environment Variables Setup](#environment-variables-setup)):

```bash
mkdir -p $BACKUP_HOME_DIR
```

Then generate the backup service keys:

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  generate-keys
```

This creates a `secrets.json` file in your backup home directory containing:
- `p2p_private_key`: Used for mutual TLS authentication with MPC nodes
- `local_storage_aes_key`: Used to encrypt keyshares stored locally

**Important:** Keep the `secrets.json` file secure. Anyone with access to this file can authenticate as your backup service and decrypt any keyshares stored locally.

## Step 2: Register the backup-cli

Before you can backup keyshares, you must register your backup-cli's public key with the MPC contract.

### Get the Registration Command

Run the following command to generate the NEAR CLI command for registration:

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  register \
  --mpc-contract-account-id $MPC_CONTRACT_ACCOUNT_ID \
  --near-network $NEAR_NETWORK \
  --signer-account-id $SIGNER_ACCOUNT_ID
```

This will output a complete `near` CLI command. Example output:

```bash
Run the following command to register your backup service:

near contract call-function as-transaction \
  $MPC_CONTRACT_ACCOUNT_ID \
  register_backup_service \
  json-args '{"backup_service_info":{"public_key":"ed25519:AbC123..."}}' \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '1 yoctoNEAR' \
  sign-as $SIGNER_ACCOUNT_ID \
  network-config $NEAR_NETWORK \
  sign-with-keychain \
  send
```

### Execute the Registration

Copy and run the generated command to register your backup-cli with the contract.

**Note:** The "public key" in the registration corresponds to the `p2p_private_key` created in Step 1.

### Verify Registration
```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  migration_info \
  json-args {} \
  network-config $NEAR_NETWORK \
  now
```

You should see your account and registered backup_cli public key listed, something like this:


```json
{
  "your-account.testnet": [
    {
      "public_key": "ed25519:AbC123..."
    },
    null
  ]
}
```

## Step 3: Generate and Set Encryption Key

For additional security, the backup and restore process encrypts keyshares during transport using AES encryption. You need to generate a shared encryption key (32 bytes / 64 hex characters), configure it on both your old and new nodes, and provide it to the backup-cli via `BACKUP_ENCRYPTION_KEY_HEX`.

Where you set it on a node depends on the deployment (see [Step 5](#step-5-prepare-the-new-node) for exact placement):
- **TDX / CVM node:** set `backup_encryption_key_hex` under `[mpc_node_config.secrets]` in `user-config.toml`. A CVM has no `.env` / `MPC_BACKUP_ENCRYPTION_KEY_HEX` pathway.
- **Non-TEE node:** set the `MPC_BACKUP_ENCRYPTION_KEY_HEX` environment variable.

**Important:** The key must match **exactly** between the backup-cli and the node it talks to (the old node for `get-keyshares`, the new node for `put-keyshares`) — a mismatch, including a stray trailing newline, makes the transfer fail. If set on the node it must be 64 hex characters (a malformed value stops the node from starting); if left unset, the node generates one itself (see below).


### Obtain the key

**Note:** If your node has been running without an encryption key configured, the node automatically generates one and stores it in a file called `backup_encryption_key.hex` in the node's home directory — `MPC_HOME_DIR` in the node's `.env`, commonly `/data` inside the container. On a **non-TEE** node you can read it on the node host — inside the container, or from the host directory mounted at `/data`:

```bash
cat $MPC_HOME_DIR/backup_encryption_key.hex
```

Copy the value to the backup-cli machine and set it there as `BACKUP_ENCRYPTION_KEY_HEX`. `backup-cli` reads the key from that variable — never pass it as the `--backup-encryption-key-hex` argument, where `ps` would expose it:

```bash
read -rs BACKUP_ENCRYPTION_KEY_HEX && export BACKUP_ENCRYPTION_KEY_HEX   # paste the 64-hex value; read -rs keeps it out of shell history
```

**TEE (TDX/dstack) nodes:** the node's home directory (`/data`) is inside the CVM's encrypted disk, so you cannot read the auto-generated `backup_encryption_key.hex`. Provide the key yourself instead. Generate one — it is just 32 random bytes, hex-encoded:

```bash
openssl rand -hex 32
```

Set it in the `[mpc_node_config.secrets]` block of the node's `user-config.toml` (see [Prepare MPC Node Configuration](https://github.com/near/mpc/blob/main/docs/guide/running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#prepare-mpc-node-configuration) in the operator guide) and keep a copy outside the CVM:

```toml
[mpc_node_config.secrets]
backup_encryption_key_hex = "<your 32-byte hex key>"
```

This is the key you pass to the backup-cli — if the node is already deployed, it is the value you set in `backup_encryption_key_hex` at deploy time. The node reads it from the config on every start, so you can add or change it on a running node via `update-user-config` + restart.



**Note on key differences:**
- `BACKUP_ENCRYPTION_KEY_HEX` (this key) is used to encrypt keyshares during transport between nodes and the backup-cli
- `local_storage_aes_key` (from Step 1) is used to encrypt keyshares stored on disk in the backup home directory
- These are two different keys serving different purposes


**TEE Migration Note:** This guide covers the Soft Launch migration process where the encryption key can be accessed from the file system. For TEE-to-TEE migrations in the Hard Launch phase, the backup service will run autonomously within a TEE and handle encryption keys securely without file system access. Refer to [migration-service.md](../archive/design/migration-service.md) for Hard Launch details.


## Step 4: Backup Keyshares from Old Node

Now backup the keyshares from your currently running node.

### Obtain Node Information

You'll need:
- **MPC node address** (`$OLD_NODE_MIGRATION_ADDRESS`): The host where your node is running, as bare `host:port` (e.g. `node.example.com:8079`). The host is available from the contract — your participant entry's `url` in the `state` view. The contract rejects a `url` longer than 256 bytes.
- **MPC node P2P public key** (`$OLD_NODE_P2P_KEY`): The Ed25519 public key used for P2P communication. Available from the contract (your participant's `tls_public_key` in `state` / `get_tee_accounts`), or from the node's public-data endpoint:

  ```bash
  export OLD_NODE_P2P_KEY=$(curl -s http://$OLD_NODE_HOST:8080/public_data | jq -r ".near_p2p_public_key")
  ```

While the old node is still reachable, also capture its signer public key — you will revoke it from your account in [Step 9](#step-9-decommission-old-node), after the node is gone:

```bash
export OLD_NODE_SIGNER_PUBLIC_KEY=$(curl -s http://$OLD_NODE_HOST:8080/public_data | jq -r ".near_signer_public_key")
```

### Get Contract State

Before backing up keyshares, you need to query the current contract state and save it:

```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  state \
  json-args {} \
  network-config $NEAR_NETWORK \
  now > $BACKUP_HOME_DIR/contract_state.json
```

This saves the contract state to `contract_state.json`, which the backup-cli uses to determine the current epoch and which keyshares to request from the node (based on the domains in the current keyset).

### Run the Backup

The migration endpoint listens on the node's `migration_web_ui` port — the port in `$OLD_NODE_MIGRATION_ADDRESS`. `8079` is the current default, but nodes configured before that default was introduced commonly use `8081`. Read the actual value from the node instead of assuming:

```bash
curl -s http://$OLD_NODE_HOST:8080/debug/node_config | jq -r '.migration_web_ui | split(":") | last'
```

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  get-keyshares \
  --mpc-node-address $OLD_NODE_MIGRATION_ADDRESS \
  --mpc-node-p2p-key $OLD_NODE_P2P_KEY
```

The encryption key comes from `$BACKUP_ENCRYPTION_KEY_HEX` ([Step 3](#step-3-generate-and-set-encryption-key)) rather than a `--backup-encryption-key-hex` argument, which `ps` would expose.

Each request to the node is bounded by `--request-timeout-seconds` (default 30). If the transfer fails with a timeout on a slow link, raise it.

> **No `http://` in `--mpc-node-address`** — it takes a bare `host:port`. With a scheme, the lookup fails with `Name or service not known`.

The encrypted keyshares are now stored in `$BACKUP_HOME_DIR/permanent_keys/epoch_<EPOCH>_with_<NUM_DOMAINS>_domains`, with `$BACKUP_HOME_DIR/key` as a hard link to the newest one. Both entries point at the same file, and the backup service reads only `key`.

### Keeping the Backup Up to Date

`get-keyshares` is a one-shot backup of the keyset that is current when you run it. Every resharing produces a new epoch, and a backup of an older epoch cannot be restored into the network, so the backup has to be retaken after each one. Instead of repeating the two steps above by hand, run `backup-cli run`, which reads the contract state itself over a NEAR JSON-RPC endpoint (`$BACKUP_RPC_URL` from [Environment Variables Setup](#environment-variables-setup)) and takes a backup whenever the contract's keyset is not the one already stored:

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  run \
  --near-chain-id $NEAR_NETWORK \
  --mpc-contract-account-id $MPC_CONTRACT_ACCOUNT_ID \
  --mpc-node-address $OLD_NODE_MIGRATION_ADDRESS \
  --mpc-node-p2p-key $OLD_NODE_P2P_KEY
```

Notes:

- No `contract_state.json` is needed: the state comes from `--rpc-url` (here via `BACKUP_RPC_URL`). `--near-chain-id` is required by the RPC client but unused by view calls.
- The endpoint is probed at startup: if the contract state cannot be read within `--request-timeout-seconds`, the service exits non-zero instead of running without backups. When starting at boot, before the network is up, rely on the supervisor's restart policy.
- The encryption key again comes from `BACKUP_ENCRYPTION_KEY_HEX` (Step 3), never the command line, where `ps` would expose it for the lifetime of the service.
- Keyshares already backed up are never re-fetched or overwritten, so restarting the service is safe and older epochs' files are kept.
- It re-reads the contract every `--poll-interval-seconds` (default 60) and acts only when the state actually changed. A successful backup logs at `info`, a failed one at `warn`, and a failed backup is re-attempted after the same interval. Logs default to `info`; `RUST_LOG` overrides that.
- `--listen-address <ip:port>` (or `BACKUP_LISTEN_ADDRESS`) serves monitoring endpoints: `/health` answers `OK`, `/status` reports the last backup as JSON, and `/metrics` exposes the Prometheus gauges `backup_cli_last_backup_epoch` and `backup_cli_last_backup_timestamp_seconds`. When unset (the default), nothing is served. After a restart the backup time is unknown, so until the next backup `/status` reports `timestamp_seconds: null` and the timestamp gauge is absent — an alert on that gauge returns no data then, rather than firing.
- This is the backup direction only. Restoring (Steps 6–8) stays manual.

See [Automatic backups](../archive/design/migration-service.md#automatic-backups-backup-cli-run) for what the service does and does not guarantee, including the RPC endpoint's role.


## Step 5: Prepare the New Node

Set up your new node on the new host with the following:

1. **Install and configure the MPC node software** on the new host (the new node should use the same NEAR account as the old node)
2. **Set the encryption key** on the backup-cli and the new node — the key `put-keyshares` reads from `BACKUP_ENCRYPTION_KEY_HEX` in [Step 7](#step-7-transfer-keyshares-to-new-node) (it may differ from the old node's key, but re-using one key throughout is simplest). Where to set it on the new node:

   - **TDX / CVM node:** set it in `user-config.toml` under `[mpc_node_config.secrets]` before deploying. On a running CVM, apply it with `update-user-config` + restart (see [CVM management](https://github.com/near/mpc/blob/main/docs/guide/running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#cvm-management)):
     ```toml
     [mpc_node_config.secrets]
     backup_encryption_key_hex = "<value>"
     ```
   - **Non-TEE node:** add it to the `.env` file:
     ```env
     MPC_BACKUP_ENCRYPTION_KEY_HEX=<value>
     ```


3. **Start the node and retrieve the new keys from the new node**: (P2P (TLS) key, NEAR account key)
4. **Add the node's `near_signer_public_key` to your account as a restricted access key**


See more details on extracting key from the node and adding the keys to your account, in the [running an MPC node in TDX external guide](https://github.com/near/mpc/blob/main/docs/guide/running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#add-the-node-account-key-to-your-account)


**Note:** The keys can be retrieved using the node's public data endpoint:

```bash
export NEW_NODE_SIGNER_PUBLIC_KEY=$(curl -s http://$NEW_NODE_HOST:8080/public_data | jq -r ".near_signer_public_key")
export NEW_NODE_P2P_KEY=$(curl -s http://$NEW_NODE_HOST:8080/public_data | jq -r ".near_p2p_public_key")
```

### Check that the new node's attestation is registered on the contract

```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  get_tee_accounts \
  json-args {} \
  network-config $NEAR_NETWORK \
  now
```

**Note:** If the new node's attestation was submitted successfully, you should see 2 attestations registered on the contract — one for the old node and one for the new node. If only the old node's entry appears and the new node's logs keep repeating `failed to submit attestation`, check `available_attestation_grants` for your account; if it is `0`, prepay a grant — see [Prepay the New Node's Attestation Storage](#prepay-the-new-nodes-attestation-storage). The rejected `submit_participant_info` transaction (its hash is logged as `sending tx …`) shows `no attestation storage grant available` in an explorer or via `near transaction view-status`. The node retries the submission on its own once a grant exists.

Output should look like this:

```bash
[
  {
    "account_id": "your-account.testnet",
    "account_public_key": "ed25519:OldNodeAccountPublicKey...",
    "tls_public_key": "ed25519:OldNodeTlsPublicKey..."
  },
  {
    "account_id": "your-account.testnet",
    "account_public_key": "ed25519:NewNodeAccountPublicKey...",
    "tls_public_key": "ed25519:NewNodeTlsPublicKey..."
  }
]
```

## Step 6: Initiate Migration state in Contract

### Collect New Node Information

You'll need:
- **New node's P2P public key**: `$NEW_NODE_P2P_KEY` from the step above.
- **New node's signer account public key**: `$NEW_NODE_SIGNER_PUBLIC_KEY` from the step above.
- **New node's public URL**: `$NEW_NODE_URL` — where peers will reach the new node (must include the `http://` prefix), not the migration endpoint in `$NEW_NODE_MIGRATION_ADDRESS`.

### start_node_migration on contract

Call the `start_node_migration` method on the MPC contract to register the new node as the migration target:

```bash
near contract call-function as-transaction \
  $MPC_CONTRACT_ACCOUNT_ID \
  start_node_migration \
  json-args "{
    \"destination_node_info\": {
      \"signer_account_pk\": \"$NEW_NODE_SIGNER_PUBLIC_KEY\",
      \"destination_node_info\": {
        \"url\": \"$NEW_NODE_URL\",
        \"tls_public_key\": \"$NEW_NODE_P2P_KEY\"
      }
    }
  }" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '1 yoctoNEAR' \
  sign-as $SIGNER_ACCOUNT_ID \
  network-config $NEAR_NETWORK \
  sign-with-keychain \
  send
```

### Verify Migration Was Registered on the Contract

After calling `start_node_migration`, verify that the destination node was registered correctly on-chain:

```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  migration_info \
  json-args {} \
  network-config $NEAR_NETWORK \
  now
```

This will return migration information for all accounts, including your backup service info and destination node info. Look for your account in the output to confirm the migration was registered.

## Step 7: Transfer Keyshares to New Node

As in [Step 4](#step-4-backup-keyshares-from-old-node), the port in `$NEW_NODE_MIGRATION_ADDRESS` is the node's `migration_web_ui` port — read it from `http://$NEW_NODE_HOST:8080/debug/node_config` instead of assuming the `8079` default. The encryption key again comes from `$BACKUP_ENCRYPTION_KEY_HEX`; the new node must hold the matching key ([Step 5](#step-5-prepare-the-new-node)).

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  put-keyshares \
  --mpc-node-address $NEW_NODE_MIGRATION_ADDRESS \
  --mpc-node-p2p-key $NEW_NODE_P2P_KEY
```

Each request to the node is bounded by `--request-timeout-seconds` (default 30). If the transfer fails with a timeout on a slow link, raise it.

The command fails without contacting the node when `$BACKUP_HOME_DIR` holds no keyshares; take a backup ([Step 4](#step-4-backup-keyshares-from-old-node)) first. On success the new node logs `set_keyshares accepted keyshares` with the number received.

The new node will:
1. Receive the encrypted keyshares
2. Decrypt them using its configured backup encryption key (Step 5)
3. Automatically call `conclude_node_migration` on the contract to finalize the migration
4. Begin participating in the MPC network with the restored keyshares

## Step 8: Verify Migration Success

Check that the migration completed successfully:

1. **Check contract state**: Query the contract to verify your account now points to the new node's public key
2. **Monitor new node logs**: Ensure the new node is participating in signature and CKD requests
3. **Test functionality**: Send a test signature request to verify the network recognizes the new node

### Query Migration State

You can check the current migration state using the contract's view methods:

```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  migration_info \
  json-args {} \
  network-config $NEAR_NETWORK \
  now
```

Look for your account in the output. Once the migration is complete, there should be no ongoing migration (destination_node_info should be null) for your account.

## Step 9: Decommission Old Node

After verifying the migration was successful:

1. **Stop the old node** on the old host.

2. **Revoke the old node's signer key.** The function-call key you added in Step 5 of the previous migration persists on your account with `unlimited` allowance on the MPC contract until explicitly removed. You captured it as `$OLD_NODE_SIGNER_PUBLIC_KEY` in [Step 4](#step-4-backup-keyshares-from-old-node); confirm with `list-keys` that it is still on the account (and distinct from the key you just added in Step 5), then revoke it with `delete-keys`:

   ```bash
   near account list-keys \
     $SIGNER_ACCOUNT_ID \
     network-config $NEAR_NETWORK \
     now

   near account delete-keys \
     $SIGNER_ACCOUNT_ID \
     public-keys $OLD_NODE_SIGNER_PUBLIC_KEY \
     network-config $NEAR_NETWORK \
     sign-with-keychain \
     send
   ```

   The `public-keys` argument is a comma-separated list (`<k1>,<k2>,…`), so if more than one stale function-call key has accumulated from earlier migrations, you can revoke them all in a single call.

   Don't revoke the `backup-cli`'s registered key from Step 2 — that's the backup service registration, reused across migrations.

3. **Keep the backup** of keyshares (the contents of `$BACKUP_HOME_DIR`, including the `key` file and the `permanent_keys/` directory with `epoch_<...>_with_<...>_domains` files) for a reasonable period (in case you need to migrate again).

4. **Securely delete** the old node's data once you're confident the new node is functioning correctly.

## Troubleshooting

### Connection Errors with backup-cli

If backup-cli cannot connect to your node:

- **`failed to lookup address information: Name or service not known`**: `--mpc-node-address` must be a bare `host:port` with no URL scheme and no trailing path. A value like `http://node.example.com:8079` is parsed as hostname `http://node.example.com`, which no resolver can answer.
- **Verify the port**: The migration endpoint uses the node's `migration_web_ui` port, which is not always the `8079` default — read it from `http://$OLD_NODE_HOST:8080/debug/node_config` (use `$NEW_NODE_HOST` for the new node). The same endpoint shows the bind address, which must not be loopback-only.
- **Verify firewall rules**: Ensure the backup service can reach the node's address and that the migration port is open and accessible. Test with `nc -vz <host> <port>` rather than `curl`; the endpoint is a raw TLS channel authenticated against the registered backup-service key, so it does not answer plain HTTP requests.

### `put-keyshares` reports success but the node never onboards

If the new node does not conclude the migration, check its logs for a warning that the registered
destination TLS key is not its own; it names both keys. That means the `tls_public_key` passed to
`start_node_migration` in [Step 6](#step-6-initiate-migration-state-in-contract) is not the key the
new node runs with. Compare `migration_info` against
`curl -s http://$NEW_NODE_HOST:8080/public_data | jq -r .near_p2p_public_key` and call
`start_node_migration` again with the correct value; only the last call is retained. The node still
holds the transferred keyshares in memory and imports them as soon as it sees itself registered,
so `put-keyshares` only needs re-running if the node restarted in the meantime.

## Known Limitations

The back-migration flow (returning to a previously-active node, i.e. A → B → A) has two operator-facing limitations:

1. **Restart Node A before initiating the back-migration.** Stop and start A so its migration service is reinitialized and ready to receive keyshares from B. The restart also forces A to submit a fresh on-chain attestation (see next bullet).

2. **A's on-chain attestation must be current.** The contract rejects the back-migration if A's attestation has expired or been revoked while A was outside the participant set. Restarting A (limitation 1) forces a fresh attestation submission immediately; otherwise, A's normal periodic resubmission updates the attestation roughly every hour.
