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

Build the backup-cli from the repository:

```bash
cd /path/to/mpc/repository
cargo build --release -p backup-cli
```

The binary will be available at `target/release/backup-cli`.

### Generate Backup Service Keys

Create a home directory for the backup service and generate its keys:

```bash
export BACKUP_HOME_DIR=/path/to/backup/home
mkdir -p $BACKUP_HOME_DIR

./target/release/backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  generate-keys
```

This creates a `secrets.json` file in your backup home directory containing:
- `p2p_private_key`: Used for mutual TLS authentication with MPC nodes
- `local_storage_aes_key`: Used to encrypt keyshares stored locally

**Important:** Keep the `secrets.json` file secure. Anyone with access to this file and your encryption key can access your node's keyshares.

## Step 2: Register the Backup Service

Before you can backup keyshares, you must register your backup service's public key with the MPC contract.

### Get the Registration Command

Run the following command to generate the NEAR CLI command for registration:

```bash
./target/release/backup-cli \
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

Set this environment variable on both your old and new MPC nodes before proceeding:

```bash
export MPC_BACKUP_ENCRYPTION_KEY_HEX=$BACKUP_ENCRYPTION_KEY
```

## Step 4: Backup Keyshares from Old Node

Now backup the keyshares from your currently running node.

### Obtain Node Information

You'll need:
- **MPC node address**: The host:port where your node is running (e.g., `node.example.com:3000`)
- **MPC node P2P public key**: The Ed25519 public key used for P2P communication (found in your node's startup logs or configuration)

### Run the Backup

```bash
./target/release/backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  get-keyshares \
  --mpc-node-address node.example.com:3000 \
  --mpc-node-p2p-key "ed25519:YourNodeP2PPublicKey..." \
  --backup-encryption-key-hex $BACKUP_ENCRYPTION_KEY
```

The encrypted keyshares are now stored in `$BACKUP_HOME_DIR/keyshares.json`.

## Step 5: Prepare the New Node

Set up your new node on the new host with the following:

1. **Install and configure the MPC node software** on the new host
2. **Generate new keys for the new node** (P2P keys, signer keys, etc.)
3. **Set the same encryption key**:
   ```bash
   export MPC_BACKUP_ENCRYPTION_KEY_HEX=$BACKUP_ENCRYPTION_KEY
   ```
4. **Do not start the node yet** - it needs the keyshares first

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
        "sign_pk": "ed25519:NewNodeP2PPublicKey...",
        "cipher_pk": "secp256k1:NewNodeCipherPublicKey..."
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

**Note:** Replace the public keys and URL with your actual new node's values. The `sign_pk` is the P2P public key, and `signer_account_pk` is the account public key used for signing contract transactions.

## Step 7: Restore Keyshares to New Node

Start your new node (which should have `MPC_BACKUP_ENCRYPTION_KEY_HEX` set), then transfer the keyshares:

```bash
./target/release/backup-cli \
  --home-dir $BACKUP_HOME_DIR \
  put-keyshares \
  --mpc-node-address new-node.example.com:3000 \
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
  get_node_migrations \
  json-args '{"account_id": "your-account.testnet"}' \
  network-config testnet \
  now
```

Once the migration is complete, there should be no ongoing migration for your account.

## Step 9: Decommission Old Node

After verifying the migration was successful:

1. **Stop the old node** on the old host
2. **Keep the backup** of keyshares in `$BACKUP_HOME_DIR/keyshares.json` for a reasonable period (in case you need to migrate again)
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

3. **Keyshares Storage**: The `keyshares.json` file contains your encrypted keyshares. Even though they're encrypted, treat this file as highly sensitive.

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
