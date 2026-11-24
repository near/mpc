# Running a backup service in TDX

A backup service keeps an encrypted copy of your MPC node's key shares, so you can restore them into a new node when you lose or move the old one. It runs `backup-cli` in a TDX CVM of its own, started by the MPC launcher. The MPC contract registers a backup service only together with its attestation, and MPC nodes exchange key shares only with a backup service whose attestation is valid.

Once running, the service:

- generates a TLS key and a NEAR account key inside the CVM and keeps them on the CVM's encrypted disk;
- registers itself on the MPC contract every hour with a fresh attestation, signed with that account key;
- reads your node's TLS key and URL from the contract and, after every resharing, fetches the new key shares from the node's migration port and stores them encrypted on the CVM's disk;
- sends the key shares to the destination node while your account has an ongoing migration to a node with a valid TDX attestation.

The service reads the chain only through a NEAR node embedded in it, and the launcher takes the contract account id and the chain's genesis hash from the measured compose file. So the CVM host cannot point the service at another contract or chain, and the MPC nodes it talks to come from that contract. [Backup Service Attestation Data](../design/backup-service-attestation-data.md) describes the design.

## Prerequisites

- Your account is a participant of the MPC network. The contract registers backup services of participants only.
- The participants have allowed a backup service image and launcher, so both views below return at least one hash. Participants allow them with `vote_backup_service_code_hash` and `vote_add_backup_service_launcher_hash`, as for the [MPC node image](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#mpc-node-image-upgrade) and [launcher](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#launcher-image-voting). [Reproducible builds](reproducible-builds.md#nix-built-images) shows how to rebuild the `backup-service-image` and check its digest. The launcher must support [`LAUNCHED_SERVICE`](../../crates/tee-launcher/README.md); an older one, such as an MPC node launcher from before backup services ran in TDX, cannot start a backup service.

  ```bash
  # Backup service image digests, newest first
  near contract call-function as-read-only $MPC_CONTRACT_ID \
    allowed_backup_service_code_hashes json-args '{}' network-config $NEAR_NETWORK now

  # Backup service launcher digests, newest last
  near contract call-function as-read-only $MPC_CONTRACT_ID \
    allowed_backup_service_launcher_image_hashes json-args '{}' network-config $NEAR_NETWORK now
  ```

- A TDX host set up as in [TDX and Dstack Setup](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#tdx-and-dstack-setup), other than the one running your MPC node.
- Your node's `backup_encryption_key_hex` set explicitly, as in [Step 3 of the node migration guide](node-migration-guide.md#step-3-generate-and-set-encryption-key). The backup service uses the same key.
- Your node's migration port (`migration_web_ui`, 8079 by default) reachable from the backup service host.
- `near`, `jq` and [`attestation-cli`](../../crates/attestation-cli/README.md) on a machine you trust.

The commands below use these variables:

```bash
export NEAR_NETWORK=testnet                    # or mainnet
export MPC_CONTRACT_ID=v1.signer-prod.testnet  # mainnet: v1.signer
export NEAR_GENESIS_HASH=FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b  # mainnet: EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H
export ACCOUNT_ID=<your MPC node account>
export BACKUP_SERVICE_HOST=<public IP of the backup service CVM>
```

## Step 1: Prepay one more attestation storage grant

The backup service's attestation takes an attestation storage grant from your account's pool, which your MPC nodes share. Prepay one grant more than your nodes need, as in [Prepay Your Node's Attestation Storage](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#prepay-your-nodes-attestation-storage), which also shows how to read the current fee:

```bash
# attached-deposit must equal the current fee exactly
near contract call-function as-transaction $MPC_CONTRACT_ID prepay_attestation_storage \
  json-args "{\"account_id\":\"$ACCOUNT_ID\",\"grants\":1}" \
  prepaid-gas '30.0 Tgas' attached-deposit '0.02 NEAR' \
  sign-as $ACCOUNT_ID network-config $NEAR_NETWORK sign-with-keychain send
```

Re-attesting or replacing your backup service takes no further grant.

## Step 2: Prepare the user config

Copy [`backup-service-user-config.toml`](../../deployment/cvm-deployment/backup-service-user-config.toml) and set:

| Field | Value |
| --- | --- |
| `account_id` | `$ACCOUNT_ID` |
| `near_init.chain_id` | `$NEAR_NETWORK` |
| `mpc_node_migration_port` | your node's migration port. During a migration the service connects to the new node on this port too, so give both nodes the same one. |
| `near_init.tier3_public_addr` | `$BACKUP_SERVICE_HOST:24567` |
| `secrets.secret_store_key_hex` | a new random key, from `openssl rand -hex 16`. It encrypts the key shares on the CVM's disk. |
| `secrets.backup_encryption_key_hex` | your node's `backup_encryption_key_hex` |

The launcher adds the contract account id and the genesis hash from the measured compose file, and rejects a config that sets them to other values.

## Step 3: Deploy the CVM

Deploy with `deploy-launcher.sh` as for an MPC node (see [Configuring and Starting the MPC Binary in a CVM](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#configuring-and-starting-the-mpc-binary-in-a-cvm)), with an `.env` file of its own in which:

- `LAUNCHER_MANIFEST_DIGEST` is the newest `allowed_backup_service_launcher_image_hashes` entry;
- `MPC_MANIFEST_DIGEST` is the newest `allowed_backup_service_code_hashes` entry;
- `USER_CONFIG_FILE_PATH` is the config from [Step 2](#step-2-prepare-the-user-config);
- `APP_NAME` names the backup service.

Point `COMPOSE_TEMPLATE` at the backup service template, whose compose hashes the contract allows for backup services:

```bash
cd deployment/cvm-deployment
COMPOSE_TEMPLATE=../../crates/contract/assets/backup_service_launcher_docker_compose.yaml.template \
  ./deploy-launcher.sh --env-file backup-service.env --base-path /path/to/meta-dstack/dstack
```

The script sizes the CVM like an MPC node CVM, which the allowed OS measurements require. Of the ports it forwards, the backup service uses 8080 and 24567. The service serves its keys on `/public_data` right away, and registers itself once its embedded NEAR node has synced, which can take hours. Its container is named `backup-service`; [Accessing MPC (or Launcher) Docker Logs](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#accessing-mpc-or-launcher-docker-logs) shows how to read its logs.

## Step 4: Verify the keys

In [Step 5](#step-5-add-the-account-key) you add the service's account key as a function-call key for every method of the MPC contract, votes included. A key swapped on its way to you, for example by anyone between you and the plain-HTTP `/public_data` endpoint, would vote with your account. Check that both keys come from an allowed backup service in a genuine TDX CVM before you add them.

Save the service's public data once, and take the keys from this file only:

```bash
curl -o public_data.json http://$BACKUP_SERVICE_HOST:8080/public_data
```

From the repository root, render the compose file you deployed, with the digests from your `.env` file:

```bash
export LAUNCHER_MANIFEST_DIGEST=<as in your .env file>
export MPC_MANIFEST_DIGEST=<as in your .env file>
sed \
  -e "s|{{LAUNCHER_IMAGE_HASH}}|${LAUNCHER_MANIFEST_DIGEST#sha256:}|g" \
  -e "s|{{DEFAULT_IMAGE_DIGEST_HASH}}|${MPC_MANIFEST_DIGEST#sha256:}|g" \
  -e "s|{{MPC_CONTRACT_ID}}|${MPC_CONTRACT_ID}|g" \
  -e "s|{{NEAR_GENESIS_HASH}}|${NEAR_GENESIS_HASH}|g" \
  crates/contract/assets/backup_service_launcher_docker_compose.yaml.template \
  > backup_service_launcher_docker_compose.yaml
```

Verify the attestation against them:

```bash
attestation-cli verify \
  --file public_data.json \
  --allowed-image-hash ${MPC_MANIFEST_DIGEST#sha256:} \
  --launcher-compose-file backup_service_launcher_docker_compose.yaml
```

Continue only on `Verdict: PASS`.

## Step 5: Add the account key

Add the verified account key to your account, scoped to the MPC contract with an empty method list and unlimited allowance, like your node's key. The service pays for its hourly registration from this allowance, so a finite one eventually stops it from attesting.

```bash
near account add-key $ACCOUNT_ID \
  grant-function-call-access \
  --allowance unlimited \
  --contract-account-id $MPC_CONTRACT_ID \
  --function-names '' \
  use-manually-provided-public-key $(jq -r .near_signer_public_key public_data.json) \
  network-config $NEAR_NETWORK \
  sign-with-keychain \
  send
```

## Step 6: Check the registration and the backups

Once registered, the contract returns the service's TLS key, the `near_p2p_public_key` in `public_data.json`, for your account:

```bash
near contract call-function as-read-only $MPC_CONTRACT_ID attested_backup_service \
  json-args "{\"account_id\":\"$ACCOUNT_ID\"}" network-config $NEAR_NETWORK now
```

If it stays `null` after the embedded node has synced, check `available_attestation_grants` for your account and the service's logs.

The service then backs up the current key shares. `http://$BACKUP_SERVICE_HOST:8080/status` shows the epoch of its last backup, and your node's `mpc_last_backup_served_epoch` reaches `mpc_current_epoch_id` (see [Metrics for node operators](node-operator-metrics.md#backups)).

## Restoring into a new node

In the [node migration guide](node-migration-guide.md), set the variables from its [Environment Variables Setup](node-migration-guide.md#environment-variables-setup), make sure a grant is available for the new node as in its [Prerequisites](node-migration-guide.md#prepay-the-new-nodes-attestation-storage), and follow Steps 5, 6, 8 and 9. The backup service takes the place of the other steps, which use `backup-cli`:

- Give the new node the same `backup_encryption_key_hex` as the old one, and the backup service's `mpc_node_migration_port` as its migration port.
- After `start_node_migration`, the backup service sends the key shares to the new node, and again every minute until the new node concludes the migration. It sends them only while the new node holds a valid TDX attestation.
- Step 9 revokes `$OLD_NODE_SIGNER_PUBLIC_KEY`, which Step 4 sets. Find the old node's signer key with `near account list-keys` instead.

Keep the backup service running after the migration. It backs up the new node from then on.

## Replacing the backup service

A launcher or OS upgrade needs a new CVM, which cannot read the old CVM's disk. Replace the service only while your node runs: the new service gets its key shares from the node.

1. Deploy and register the new service, following Steps 2 to 6.
2. Once `attested_backup_service` returns the new service's TLS key, delete the old service's account key and stop its CVM:

   ```bash
   near account delete-keys $ACCOUNT_ID \
     public-keys <the old service's near_signer_public_key> \
     network-config $NEAR_NETWORK sign-with-keychain send
   ```

Each registration replaces the account's previous backup service. While both keys stay on your account, the two services replace each other every hour, and your node backs up to whichever registered last.

To upgrade only the image, restart the CVM once the participants allowed the new one, as for an [MPC node image upgrade](running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#update-the-mpc-node). The keys and key shares stay on its disk.

## Monitoring

The service serves `/health`, `/status` and `/metrics` on port 8080. `/metrics` exports:

| Metric | What it tracks |
| --- | --- |
| `backup_cli_last_backup_epoch` | the epoch of the last backup. Absent until the first one. |
| `backup_cli_last_backup_timestamp_seconds` | when the service last backed up or confirmed its copy against the node, which it does every hour. Absent after a restart until then. |
| `mpc_attestation_last_landed_timestamp_seconds` | the NEAR block time at which the contract last accepted the service's attestation |
| `mpc_attestation_expiry_timestamp_seconds` | the NEAR block time at which the stored attestation expires. `0` means none is stored, and `-1` means it carries no expiry. |
| `mpc_own_image_hash_allowed`, `mpc_own_image_hash_is_most_recent`, `mpc_own_image_hash_expiry_timestamp_seconds` | whether the running image is still allowed, and when the contract evicts it |
| `mpc_tee_attestation_attempts_total`, `mpc_tee_attestation_submissions_total`, `mpc_tee_attestation_round_timeouts_total` | attestation rounds by outcome |

It also exports the embedded NEAR node's metrics, but not the MPC node's `mpc_indexer_latest_block_timestamp_seconds`, so the alerts below compare against `time()`:

```promql
# Warn: no backup or check for a day
time() - backup_cli_last_backup_timestamp_seconds > 86400  for 2h

# Warn: no attestation accepted in three resubmission intervals
time() - mpc_attestation_last_landed_timestamp_seconds > 3 * 3600  for 15m

# Page: under three days of attestation runway left
mpc_attestation_expiry_timestamp_seconds > 0
  and mpc_attestation_expiry_timestamp_seconds - time() < 3 * 86400  for 15m

# Page: no attestation stored, so nodes do not back up to this service
# (also fires on a new service until its embedded NEAR node has synced)
mpc_attestation_expiry_timestamp_seconds == 0  for 15m
```
