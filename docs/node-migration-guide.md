# Node Migration Guide

This guide provides step-by-step instructions for node operators to migrate their MPC nodes between different hosts or cloud providers using the backup CLI.

## Overview

Node migration allows you to move your MPC node from one host to another without requiring a full network resharing. This is accomplished using the  `backup-cli` tool to securely backup and restore your node's keyshares.

**Important:** This guide covers the **Soft Launch** migration process. For information about the architecture and future Hard Launch implementation, see [migration-service.md](./migration-service.md).

## Prerequisites

Before starting a migration, ensure you have:

1. **An active MPC node** that is a current participant in the network
2. **A new host/machine** ready to run the migrated node
3. **The backup-cli tool** installed on a secure machine (can be your local machine or a dedicated backup server)
4. **NEAR CLI** installed for contract interactions
5. **Access to both nodes** (old and new) during the migration process

## Environment Variables Setup

Set up the following environment variables at the beginning of your migration process. These will be used throughout the guide:

```bash
# Your NEAR account ID that operates the MPC node
export SIGNER_ACCOUNT_ID=your-account.testnet

# The MPC contract account ID
export MPC_CONTRACT_ACCOUNT_ID=v1.signer-prod.testnet

# NEAR network configuration (testnet or mainnet)
export NEAR_NETWORK=testnet
```

**Note:** Adjust these values based on your specific setup. For mainnet deployments, use `mainnet` for `NEAR_NETWORK` and the appropriate mainnet contract account ID.

## Step 1: Setup the Backup CLI

First, you'll need to set up the backup CLI tool and generate keys for the backup service.

### Install backup-cli

Install the backup-cli tool using cargo (run from the repository root):

```bash
cargo install --path crates/backup-cli --locked
```

This installs the `backup-cli` binary to your cargo bin directory (typically `~/.cargo/bin`), which should be in your `PATH`.

### Generate Backup Service Keys

Create a home directory for the backup-cli and generate its keys:

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
  attached-deposit '0 NEAR' \
  sign-as $SIGNER_ACCOUNT_ID \
  network-config $NEAR_NETWORK \
  sign-with-keychain \
  send
```

### Execute the Registration

Copy and run the generated command to register your backup-cli with the contract.

**Note:** The "public key" in the registration corresponds to  the `p2p_private_key` created in Step 1. 

### Verify Registration
```bash
near contract call-function as-read-only \
  $MPC_CONTRACT_ACCOUNT_ID \
  migration_info \
  json-args {} \
  network-config $NEAR_NETWORK \
  now
```

You should see your account and registered backup_cli  public key listed, something like this:


```bash
{
  "your-account.testnet": [
    {
      "public_key": "ed25519:AbC123"
    },
} 
```

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

**Important:** The `MPC_BACKUP_ENCRYPTION_KEY_HEX` must be the same between the backup-cli and the node it is currently communicating with (e.g., the old node when running `get-keyshares`, and the new node when running `put-keyshares`). This key provides an additional layer of security beyond mTLS for encrypting keyshares during transport.

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

Both those values can be found on the contract. 

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

1. **Install and configure the MPC node software** on the new host (the new node should use the same NEAR account as the old node)
2. **Set the same encryption key**: on the backup-cli and the new node.
   ```bash
   export MPC_BACKUP_ENCRYPTION_KEY_HEX=$BACKUP_ENCRYPTION_KEY
   ```
Note: this key doesn't need to be the key used for getting the old node's keyshares.

3. **Start the node and retrieve the new keys from the new node**: (P2P (TLS) key, NEAR account key)   
4. **add the node's near_signer_public_key to your account as an restricted access key** 


See more details on extracting key from the node and adding the keys to your account, in the [running an MPC node in TDX external guide](https://github.com/near/mpc/blob/main/docs/running_an_mpc_node_in_tdx_external_guide.md#add-the-node-account-key-to-your-account)


**Note:** The keys can be retrieved using the node's public data endpoint:

```bash
export near_signer_public_key=$(curl -s http://<IP>:8080/public_data | jq -r ".near_signer_public_key")
export P2P_KEY=$(curl -s http://<IP>:8080/public_data | jq -r ".near_p2p_public_key")
```

### Check that the new node's attestation is registered on the contract

```bash
near contract call-function as-transaction \
  $MPC_CONTRACT_ACCOUNT_ID \
  get_tee_accounts \
  json-args {} \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as $SIGNER_ACCOUNT_ID \
  network-config $NEAR_NETWORK \
  sign-with-keychain \
  send
```

**note** - If the new node's attestation was submitted successfully, you should see 2 attestations registered on the contract - one for the old node and one for the new node.

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
- **New node's P2P public key**: $P2P_KEY from step above.
- **New node's signer account public key**: $near_signer_public_key from step above.
- **New node's address**: The URL where the new node will be accessible (e.g., `new-node.example.com:80`)

### start_node_migration on contract

Call the `start_node_migration` method on the MPC contract to register the new node as the migration target:

```bash
near contract call-function as-transaction \
  $MPC_CONTRACT_ACCOUNT_ID \
  start_node_migration \
  json-args '{
    "destination_node_info": {
      "signer_account_pk": "$near_signer_public_key",
      "destination_node_info": {
        "url": "new-node.example.com:80",
        "sign_pk": "$P2P_KEY"
      }
    }
  }' \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
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
  $MPC_CONTRACT_ACCOUNT_ID \
  migration_info \
  json-args {} \
  network-config $NEAR_NETWORK \
  now
```

Look for your account in the output. Once the migration is complete, there should be no ongoing migration (destination_node_info should be null) for your account.

## Step 9: Decommission Old Node

After verifying the migration was successful:

1. **Stop the old node** on the old host
2. **Keep the backup** of keyshares (the contents of `$BACKUP_HOME_DIR`, including the `key` file and the `permanent_keys/` directory with `epoch_<...>_with_<...>_domains` files) for a reasonable period (in case you need to migrate again)
3. **Securely delete** the old node's data once you're confident the new node is functioning correctly

## Troubleshooting

### Connection Errors with backup-cli

If backup-cli cannot connect to your node:

- **Verify firewall rules**: Ensure the backup service can reach the node's address
port 8079  is open and accessible


