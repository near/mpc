# Node Migration Guide

This guide provides step-by-step instructions for node operators to migrate their MPC nodes between different hosts or cloud providers using the backup CLI.

## Overview

Node migration allows you to move your MPC node from one host to another without requiring a full network resharing. This is accomplished using the backup service and the `backup-cli` tool to securely backup and restore your node's keyshares.

**Important:** This guide covers the **Soft Launch** migration process. For information about the architecture and future Hard Launch implementation, see [migration-service.md](./migration-service.md).

## Prerequisites

Before starting a migration, ensure you have:

1. **An active MPC node** that is a current participant in the network
2. **A new host/machine** ready to run the migrated node
3. **The backup-cli tool** installed on a secure machine (can be your local machine or a dedicated backup server)
4. **NEAR CLI** installed for contract interactions
5. **Access to both nodes** (old and new) during the migration process

## Step 1: Setup the Backup CLI

First, you'll need to set up the backup CLI tool and generate keys for the backup service.

### Install backup-cli

Install the backup-cli tool using cargo (run from the repository root):

```bash
cargo install --path crates/backup-cli --locked
```

This installs the `backup-cli` binary to your cargo bin directory (typically `~/.cargo/bin`), which should be in your `PATH`.

### Generate Backup Service Keys

Create a home directory for the backup service and generate its keys:

```bash
export BACKUP_HOME_DIR=/path/to/backup/home
mkdir -p $BACKUP_HOME_DIR

backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  generate-keys
```

This creates a `secrets.json` file in your backup home directory containing:
- `p2p_private_key`: Used for mutual TLS authentication with MPC nodes
- `local_storage_aes_key`: Used to encrypt keyshares stored locally
- `near_signer_key`: Used by the backup service to sign NEAR transactions on behalf of the service

**Important:** Keep the `secrets.json` file secure. Anyone with access to this file can authenticate as your backup service and decrypt any keyshares stored locally (because it contains `local_storage_aes_key`).

## Step 2: Register the Backup Service

Before you can backup keyshares, you must register your backup service's public key with the MPC contract.

### Get the Registration Command

Run the following command to generate the NEAR CLI command for registration:

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  register \
  --mpc-contract-account-id v1.signer-prod.testnet \
  --near-network testnet \
  --signer-account-id your-account.testnet
```

This will output a complete `near` CLI command. Example output:

```bash
Run the following command to register your backup service:

near contract call-function as-transaction \
  v1.signer-prod.testnet \
  register_backup_service \
  json-args '{"backup_service_info":{"public_key":"ed25519:AbC123..."}}' \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as your-account.testnet \
  network-config testnet \
  sign-with-keychain \
  send
```

### Execute the Registration

Copy and run the generated command to register your backup service with the contract.

**Note:** The "public key" in the registration corresponds to the public key derived from the `p2p_private_key` created in Step 1. After registration, you can verify it was registered by checking the contract's migration info (see Step 6 for details).

## Step 3: Generate and Set Encryption Key

Generate a 256-bit (32-byte) AES encryption key for securing keyshares during backup and restore:

```bash
# Generate a random 32-byte hex key
export BACKUP_ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "Your encryption key: $BACKUP_ENCRYPTION_KEY"
```

**Critical:** Save this encryption key securely. You'll need to provide it to:
1. Your **old MPC node** (via the `MPC_BACKUP_ENCRYPTION_KEY_HEX` environment variable)
2. Your **new MPC node** (via the `MPC_BACKUP_ENCRYPTION_KEY_HEX` environment variable)
3. The **backup-cli** commands (via the `--backup-encryption-key-hex` parameter)

**Important:** The `MPC_BACKUP_ENCRYPTION_KEY_HEX` must be the **same** on both old and new nodes for the migration to work. This key provides an additional layer of security beyond mTLS for encrypting keyshares during transport.

**Note on key differences:** 
- `BACKUP_ENCRYPTION_KEY` (this key) is used to encrypt keyshares during transport between nodes and the backup-cli
- `local_storage_aes_key` (from Step 1) is used to encrypt keyshares stored on disk in the backup home directory
- These are two different keys serving different purposes

**Note:** If your node has been running without the `MPC_BACKUP_ENCRYPTION_KEY_HEX` environment variable set, the node automatically generates an encryption key and stores it in a file called `backup_encryption_key.hex` in your `$MPC_HOME_DIR` directory. You can retrieve it with:

```bash
export BACKUP_ENCRYPTION_KEY=$(cat $MPC_HOME_DIR/backup_encryption_key.hex)
```

**TEE Migration Note:** This guide covers the Soft Launch migration process where the encryption key can be accessed from the file system. For TEE-to-TEE migrations in the Hard Launch phase, the backup service will run autonomously within a TEE and handle encryption keys securely without file system access. Refer to [migration-service.md](./migration-service.md) for Hard Launch details.

Set this environment variable on both your old and new MPC nodes before proceeding:

```bash
export MPC_BACKUP_ENCRYPTION_KEY_HEX=$BACKUP_ENCRYPTION_KEY
```

## Step 4: Backup Keyshares from Old Node

Now backup the keyshares from your currently running node.

### Obtain Node Information

You'll need:
- **MPC node address**: The host where your node is running (e.g., `node.example.com`)
- **MPC node P2P public key**: The Ed25519 public key used for P2P communication (found in your node's startup logs or configuration)

### Get Contract State

Before backing up keyshares, you need to query the current contract state and save it:

```bash
near contract call-function as-read-only \
  v1.signer-prod.testnet \
  state \
  json-args {} \
  network-config testnet \
  now > $BACKUP_HOME_DIR/contract_state.json
```

This saves the contract state to `contract_state.json`, which the backup-cli uses to determine the current epoch and which keyshares to request from the node (based on the domains in the current keyset).

### Run the Backup
Port 8079 is the default port for the migration endpoint.
```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  get-keyshares \
  --mpc-node-address node.example.com:8079 \
  --mpc-node-p2p-key "ed25519:YourNodeP2PPublicKey..." \
  --backup-encryption-key-hex $BACKUP_ENCRYPTION_KEY
```

The encrypted keyshares are now stored in `$BACKUP_HOME_DIR/permanent_keys/epoch_<EPOCH>_with_<NUM_DOMAINS>_domains` (with a `key` hard-link in that directory).

## Step 5: Prepare the New Node

Set up your new node on the new host with the following:

1. **Install and configure the MPC node software** on the new host
2. **Generate new keys for the new node** (P2P keys, signer keys, etc.)
3. **Set the same encryption key**:
   ```bash
   export MPC_BACKUP_ENCRYPTION_KEY_HEX=$BACKUP_ENCRYPTION_KEY
   ```

### Collect New Node Information

You'll need:
- **New node's P2P public key**: The Ed25519 public key for the new node's P2P communication
- **New node's address**: The URL where the new node will be accessible (e.g., `https://new-node.example.com:3000`)
- **New node's signer account public key**: The NEAR account public key the new node will use to sign contract transactions

## Step 6: Initiate Migration in Contract

Call the `start_node_migration` method on the MPC contract to register the new node as the migration target:

```bash
near contract call-function as-transaction \
  v1.signer-prod.testnet \
  start_node_migration \
  json-args '{
    "destination_node_info": {
      "signer_account_pk": "ed25519:NewNodeSignerPublicKey...",
      "destination_node_info": {
        "url": "https://new-node.example.com:3000",
        "sign_pk": "ed25519:NewNodeP2PPublicKey..."
      }
    }
  }' \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as your-account.testnet \
  network-config testnet \
  sign-with-keychain \
  send
```

**Note:** Replace the public keys and URL with your actual new node's values.

**Field Explanations:**
- `signer_account_pk`: The NEAR account public key (Ed25519) the new node will use to sign contract transactions
- `destination_node_info` (outer): The complete destination node information struct required by the contract
- `destination_node_info` (inner/nested): The participant information containing the node's URL and P2P signing key
- `url`: The HTTP/HTTPS endpoint where the new node will be accessible
- `sign_pk`: The P2P public key (Ed25519) used for mutual TLS authentication between nodes

**Why the nested naming?** The contract's `DestinationNodeInfo` type has a field named `destination_node_info` of type `ParticipantInfo`. While the naming may seem redundant, it matches the contract's structure and must be used exactly as shown.

### Verify Migration Was Registered on the Contract

After calling `start_node_migration`, verify that the destination node was registered correctly on-chain:

```bash
near contract call-function as-read-only \
  v1.signer-prod.testnet \
  migration_info \
  json-args {} \
  network-config testnet \
  now
```

This will return migration information for all accounts, including your backup service info and destination node info. Look for your account in the output to confirm the migration was registered.

## Step 7: Restore Keyshares to New Node

Start your new node (which should have `MPC_BACKUP_ENCRYPTION_KEY_HEX` set), then transfer the keyshares:

```bash
backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  put-keyshares \
  --mpc-node-address new-node.example.com:8079 \
  --mpc-node-p2p-key "ed25519:NewNodeP2PPublicKey..." \
  --backup-encryption-key-hex $BACKUP_ENCRYPTION_KEY
```

The new node will:
1. Receive the encrypted keyshares
2. Decrypt them using `MPC_BACKUP_ENCRYPTION_KEY_HEX`
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
  v1.signer-prod.testnet \
  migration_info \
  json-args {} \
  network-config testnet \
  now
```

Look for your account in the output. Once the migration is complete, there should be no ongoing migration (destination_node_info should be null) for your account.

## Step 9: Decommission Old Node

After verifying the migration was successful:

1. **Stop the old node** on the old host
2. **Keep the backup** of keyshares (the contents of `$BACKUP_HOME_DIR`, including the `key` file and the `permanent_keys/` directory with `epoch_<...>_with_<...>_domains` files) for a reasonable period (in case you need to migrate again)
3. **Securely delete** the old node's data once you're confident the new node is functioning correctly

## Troubleshooting

### Migration Fails to Complete

If the new node doesn't automatically call `conclude_node_migration`:

- **Check logs**: Look for errors in the new node's logs
- **Verify encryption key**: Ensure `MPC_BACKUP_ENCRYPTION_KEY_HEX` is set correctly on the new node
- **Check keyshares**: Verify the keyshares were successfully transferred (check new node's logs)
- **Verify contract state**: Ensure `start_node_migration` was called successfully

### "NotParticipant" Error

This error occurs if:
- You're not currently a participant in the network
- You're trying to call contract methods from the wrong account

Verify you're using the correct account that's registered as a participant.

### "ProtocolStateNotRunning" Error

Node migrations can only occur when the protocol is in the `Running` state. If the network is in `Resharing` or `Initializing` state, wait for it to return to `Running` before attempting migration.

### Connection Errors with backup-cli

If backup-cli cannot connect to your node:

- **Verify firewall rules**: Ensure the backup service can reach the node's address
- **Check P2P public key**: Ensure you're using the correct P2P public key for authentication
- **Check node status**: Ensure the node is running and accessible

## Security Considerations

1. **Encryption Key**: The `BACKUP_ENCRYPTION_KEY_HEX` provides an additional layer of security beyond mTLS. Never share this key or commit it to version control.

2. **Backup Service Keys**: The `secrets.json` file in your backup home directory contains sensitive keys. Store it securely and restrict access.

3. **Keyshares Storage**: `backup-cli` stores your encrypted keyshares under `$BACKUP_HOME_DIR/key` and `$BACKUP_HOME_DIR/permanent_keys/...`, encrypted with `local_storage_aes_key`. Even though they're encrypted, treat these files and directories as highly sensitive.

4. **Network Security**: Use secure, encrypted connections when running backup-cli commands. Consider running the backup service on a secure, isolated network.

## Migration Limitations

- **Protocol State**: Migrations can only be performed when the protocol is in `Running` state
- **One Migration at a Time**: You can only have one ongoing migration per account
- **Automatic Cancellation**: If the protocol transitions to `Resharing` or `Initializing` state during migration, your migration will be automatically cancelled

## Related Documentation

- [migration-service.md](./migration-service.md) - Detailed architecture and design of the migration service
- [migration-service-how-to.md](./migration-service-how-to.md) - Quick reference for node operator responsibilities
- [running_an_mpc_node_in_tdx.md](./running_an_mpc_node_in_tdx.md) - Guide for running nodes in TEE environments

## Additional Notes

This guide covers the Soft Launch migration process where backup-cli is run manually by the operator. In the future Hard Launch, the backup service will run autonomously in a TEE and handle migrations automatically with minimal operator intervention.

For questions or issues, please refer to the project's issue tracker or reach out to the MPC network support channels.
