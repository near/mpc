# Migration Service TEE integration

This documents outlines the design and efforts for runnnig the migration and backup service inside a trusted execution environment (c.f. [miration-service](docs/migratoion-service.md) for more details on the migration and backup service, as well as for the motivation of running it inside a TEE).


## Implementation Design

We need two things to succesfully run the migration and backup service inside TEE's:
1. The migration and backup service must have a current view of the NEAR blockchain. It is preferred that they, similar to the MPC node, run an indexer.
2. The migration and backup service must be able to run inside a TEE and must submit proof of that to the MPC smart contract.


### Indexer

It is preferred to re-use code where applicable. It is also a stated goal that the indexer is moved into its own crate. On a high-level, we expect to be doing the following:

1. Clean up the indexer API in the MPC node, such that it will be easy to separate it from the node.
2. Move the indexer code into its own crate.
3. Add the indexer crate as a dependency to the migration and backup service.

We will focus on the first step here.

#### Proposed Indexer API

In the not so near future, we expect to be able to run the indexer as a stand-alone binary, such that it can be used for monitoring the smart contracts of our testing and production environments. This will be a larger effort, as communication with such a binary will most likely take place over OS or web sockets, requiring a more structured communication between the indexer and the MPC node.

For the time being, we can still rely on channels.

This is the current IndexerAPI:

```rust
/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
pub struct IndexerAPI<TransactionSender> {
    /// Provides the current contract state as well as updates to it.
    pub contract_state_receiver: watch::Receiver<ContractState>,
    /// Provides block updates (signature requests and other relevant receipts).
    /// It is in a mutex, because the logical "owner" of this receiver can
    /// change over time (specifically, when we transition from the Running
    /// state to a Resharing state to the Running state again, two different
    /// tasks would successively "own" the receiver).
    /// We do not want to re-create the channel, because while resharing is
    /// happening we want to buffer the signature requests.
    pub block_update_receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ChainBlockUpdate>>>,
    /// Handle to transaction processor.
    pub txn_sender: TransactionSender,
    /// Watcher that keeps track of allowed [`DockerImageHash`]es on the contract.
    pub allowed_docker_images_receiver: watch::Receiver<Vec<MpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,
}
```

Note that it mixes a few things:


the backup and migration service would only require the following:
```rust
/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
pub struct IndexerAPI<TransactionSender> {
    /// Provides the current contract state as well as updates to it.
    pub contract_state_receiver: watch::Receiver<ContractState>,
    /// Handle to transaction processor.
    pub txn_sender: TransactionSender,
    /// Watcher that keeps track of allowed [`DockerImageHash`]es on the contract.
    pub allowed_docker_images_receiver: watch::Receiver<Vec<MpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,
}
```



### Smart contract changes

##### Hard Launch
#### Backup 

For the hard launch, the above steps will not be run manually, but automatically:
- The backup service runs a NEAR node and monitors the MPC smart contract;
- The backup service compares the keyshares it has in its possession with the keyshares it is supposed to have (the contract [keeps track](https://github.com/near/mpc/blob/2d833aee6eab1e7a796348787028f3392cafe1bd/crates/contract/src/state/running.rs#L27-L29) of what keys are currently used);
- If the backup service is missing keyshares, it requests them from the MPC node (similar to steps 2.1-2.4 in the [Soft Launch](#soft-launch) section).
Additionally, the MPC node will have to verify the attestation submitted by the backup service.

```mermaid
---
title: Backup Flow (Hard Launch with TEE Attestation)
---
flowchart TD
    SC("
      **Smart Contract**
      _Source of truth for
      protocol state and
      node information._
    ");
    MPC("
      **MPC Node (TEE)**
      _Currently participating in the MPC network.
      Holds sensitive key shares_.
    ");
    BS("
      **Backup Service (TEE)**
      _Stores encrypted backups
      of key shares.
      Uniquely identified by a public key._
    ");
    
    BS -->|"1. register backup service with attestation (resubmitted periodically)"| SC
    SC -->|"2. verify TEE attestation and Docker image hash"| SC
    BS -->|"3. read MPC node Public Key and address"| SC
    BS -->|"4. request encrypted keyshares (mTLS)"| MPC
    MPC -->|"5. verify attestation and read backup service Public Key"| SC
    MPC -->|"6. send encrypted key shares"| BS
    
    SC@{shape: cylinder}
    MPC@{shape: proc}
    BS@{shape: proc}
```


#### Recovery/Migration
##### Hard Launch

For the hard launch, the recovery flow is the same as in the soft launch, but more automated: the backup service monitors the contract state and initiates migrations automatically (e.g., by calling `conclude_node_migration(keyset)`). The operator only needs to initiate the process by calling `start_node_migration`.

There's also an additional TEE-attestation step: the new node must verify that the smart contract successfully verified the backup service's attestation before saving the received keyshares, and the contract must verify the backup service's attestation before handing over the public key and address of the new MPC node.

```mermaid
---
title: Recovery Flow (Hard Launch with TEE Attestation)
---
flowchart TD
    NO["**Node Operator**
      _Owner of the MPC node and Backup Service._"]

    SC["**Smart Contract**
      _Source of truth for
      protocol state and
      node information._"]

    BS@{ label: "**Backup Service (TEE)**
        _Stores encrypted backups of key shares.
        Uniquely identified by a public key._" }

    MPC["**New MPC Node (TEE)**
      _Needs keyshares from backup service._"]

    NO -->|"1. start onboarding for new node with attestation in smart contract"| SC
    BS -->|"2. monitor for migration events"| SC
    SC -->|"3. new migration"| BS
    BS -->|"4. request new MPC node Public Key and address"| SC
    SC -->|"5. verify backup service attestation"| SC
    SC -->|"6. send new MPC node Public Key and address"| BS
    BS -->|"7. send encrypted key shares (mTLS)"| MPC
    MPC -->|"8. verify backup service attestation before saving keyshares"| SC
    MPC -->|"9. resolve recovery and participate in the network"| SC

    NO@{ shape: manual-input}
    SC@{ shape: db}
    BS@{ shape: proc}
    MPC@{ shape: proc}
```



## Implementation Details

### Contract

For the soft launch, the structures backing the migration service look as follows:

```rust
/// Manages backup service registration and ongoing node migrations
pub struct NodeMigrations {
    /// Maps AccountId to backup service info (public key for TLS authentication)
    backup_services_info: IterableMap<AccountId, BackupServiceInfo>,

    /// Maps AccountId to destination node info for in-progress migrations
    ongoing_migrations: IterableMap<AccountId, DestinationNodeInfo>,
}

/// Backup service authentication information
pub struct BackupServiceInfo {
    /// Ed25519 public key for mutual TLS authentication
    pub public_key: Ed25519PublicKey,
}

/// Destination node information during migration
pub struct DestinationNodeInfo {
    /// NEAR account public key (for verifying contract transaction signatures)
    pub signer_account_pk: near_sdk::PublicKey,

    /// New node's participant info (TLS key, cipher key, URL, etc.)
    pub destination_node_info: ParticipantInfo,
}
```


**Hard Launch Extensions:**

For hard launch, `NodeMigrations` will be extended with the existing `TeeState` struct, which contains attestation, timestamp, and all TEE-related verification data. The global `TeeState` maintains allowed Docker image and launcher hash lists for backup services (separate from MPC node images), managed through existing voting mechanisms.

```
/// Manages backup service registration and ongoing node migrations
pub struct NodeMigrations {
    /// Maps AccountId to backup service info (public key for TLS authentication)
    backup_services_info: IterableMap<AccountId, BackupServiceInfo>,

    /// Maps AccountId to destination node info for in-progress migrations
    ongoing_migrations: IterableMap<AccountId, DestinationNodeInfo>,

    /// Global TEE state for backup services (for hard launch)
    /// Contains shared allowed Docker image hashes, launcher hashes, and voting state
    pub backup_service_tee_state: TeeState,
}
```

Additionally, the backup service will need to provide a TEE attestation similar to MPC nodes, which requires extending the contract to support attestation verification for backup services. (TODO(#947): Define attestation data for backup service)

#### Backup Service Registration

The backup service attestation registreation and verification would follow the same process as MPC node attestations:
1. Backup service generates TLS keypair inside TEE
2. Backup service generates account keypair inside TEE for signing contract transactions (required to submit the attestation to the contract)
3. Creates `ReportData` V1: `[version(2 bytes big endian) || sha384(TLS pub key || account_pubkey) || zero padding]`
4. Obtains TEE quote embedding the `ReportData`
5. Submits attestation via `register_backup_service(tls_public_key, account_public_key, attestation)`
6. Contract verifies (using existing `TeeState` verification logic):
   - Quote validity via attestation provider
   - Docker image hash against allowed list
   - Launcher compose hash (if applicable)
   - Timestamp within deadline
   - `ReportData` matches SHA3-384 hash of `SHA3-384(tls_public_key || account_public_key)`
   - Transaction signer's public key matches `account_public_key` via `env::signer_account_pk()`
7. Contract stores `TeeState` (containing attestation and all verification data)

> **Note**: Unlike MPC nodes which may need multiple attestations per operator, backup services use a simpler one-per-operator model. The `AccountId` remains the unique identifier, consistent with soft launch.

#### Backup Service TEE methods

The contract provides separate voting endpoints for backup service Docker image hashes. These are intentionally separate from MPC node voting to maintain backwards compatibility:

- **`vote_backup_service_code_hash(code_hash: BackupServiceDockerImageHash)`** - Votes to add a backup service Docker image hash to the whitelist:
    - Called by MPC node operators (must be a current participant)
    - Similar to `vote_code_hash()` but for backup service images
    - When threshold is reached, the hash is added to the allowed backup service images list
    - Can only be called when protocol is in `Running` state
    - Separate from MPC node image voting for backwards compatibility
    - Automatically generates and whitelists the corresponding launcher compose hash

- **`allowed_backup_service_code_hashes()`** - Returns all currently allowed backup service Docker image hashes:
    - Read-only view method
    - Returns hashes that are still within their validity period
    - Separate list from MPC node allowed hashes

- **`allowed_backup_service_launcher_compose_hashes()`** - Returns all allowed backup service launcher compose hashes:
    - Read-only view method
    - Launcher compose hashes are automatically generated from voted Docker image hashes
    - Used by backup service launchers to verify the correct compose file is being used
    - Separate list from MPC node launcher hashes

> **Note on Launcher Compose Hashes**: Launcher compose hashes are **not voted on directly**. When operators vote for a backup service Docker image hash via `vote_backup_service_code_hash()` and the voting threshold is reached, the contract automatically:
> 1. Computes the launcher compose hash by filling the template with the Docker image hash
> 2. Adds both the Docker image hash and launcher compose hash to their respective allowed lists
>
> This deterministic derivation ensures the launcher configuration always matches the voted Docker image, eliminating the need for separate voting. The same pattern is used for MPC nodes with `vote_code_hash()`.

#### Migration Methods

The contract provides the following methods:

- **`start_node_migration(destination_node_info: ParticipantInfo)`** - Initiates a node migration:
    - Called by the node operator
    - Creates an `OngoingNodeMigration` record for the given `AccountId`
    - Stores the destination node's `ParticipantInfo` (new TLS keys, etc.)
    - Can be called multiple times to update the destination node info (only the last value is retained)
    - Returns an error if the protocol is not in `Running` state
    - Returns an error if caller is not a current participant

- **`cancel_node_migration()`** - Cancels an ongoing node migration:
    - Called by the node operator
    - Removes the `OngoingNodeMigration` record for the given `AccountId`
    - Useful if the new node is not functioning correctly or wrong information was provided

- **`conclude_node_migration(keyset: &Keyset)`** - Finalizes a node migration:
    - Called by the new node after receiving keyshares from backup service
    - Verifies the provided `keyset` matches the expected key event IDs for this epoch
    - Replaces the old node's `ParticipantInfo` with the new node's info in the current participant set
    - Removes the `OngoingNodeMigration` record
    - Returns an error if the protocol is not in `Running` state
    - Returns an error if no ongoing migration exists for the caller

- **`register_backup_service(backup_service_info: BackupServiceInfo)`** - Registers or updates backup service:
    - Called by the node operator
    - Stores the backup service's public key and URL for the node operator's account
    - Defines or overrides the `BackupServiceInfo` for the node operator
    - Can be called in any protocol state (`Running`, `Initializing`, or `Resharing`)
    - Returns an error if caller is not a current participant

> **Hard Launch Extension (Planned):** For hard launch, `register_backup_service()` will require an `attestation` and `operator_account_pk` parameter. The contract will verify the attestation validity, Docker image hash, and that the `ReportData` includes both the TLS public key and operator's account public key (`SHA3-384(tls_public_key || operator_account_pk)`). This cryptographically binds the backup service TEE to the specific operator, preventing a malicious backup service from registering under a different operator's account. Backup services will need to refresh attestations before expiration.

#### Migration Related Behavior

- The `OngoingNodeMigration` records are automatically cleared when the protocol transitions from `Running` state to `Resharing` or `Initializing` state, effectively cancelling any in-progress migrations.
- **Future Enhancement**: It may be desirable for the contract to verify that calls to `conclude_node_migration(keyset)` come from the actual onboarding node by checking the transaction signer's public key _(see [(#1086)](https://github.com/near/mpc/issues/1086))_. This would prevent ill-behaved decommissioned nodes from making spurious migration calls. This would require:
    - Comparing `env::signer_account_pk()` with the public key associated with the participant (note: this is different from the TLS key currently stored as [`signer_pk`](https://github.com/near/mpc/blob/b5a9d1b2eef4de47d19b66cb25b577da2b897560/crates/contract/src/tee/tee_state.rs#L32) in TEEState)
    - Including this public key in the TEE attestation

### Backup Service Components

Both soft launch and hard launch implementations share common core components, with hard launch adding TEE-specific features and automation.

#### Common Components (Both Soft and Hard Launch)

1. **mTLS Client**: Establishes authenticated connections to MPC nodes using P2P keys
   - Performs mutual TLS handshake using keys registered in the contract
   - Validates peer identity against expected public key from contract

2. **Symmetric Encryption**: Uses an operator-provided environment variable for an additional encryption layer
   - Operator manually provides the same key to both MPC node and backup service: `MPC_BACKUP_ENCRYPTION_KEY_HEX` (soft launch) or `BS_BACKUP_ENCRYPTION_KEY_HEX` (hard launch)
   - Adds second layer of encryption beyond mTLS transport security
   - Extra protection if contract state becomes inconsistent or manipulated


#### Hard Launch-Specific Components

3. **Contract Transaction Interface**: Signs and submits transactions automatically
   - Calls `register_backup_service()` with attestation periodically
   - Uses account private key generated in TEE

4. **TEE Runtime**: TDX-enabled environment backed by [dstack](https://github.com/Dstack-TEE/dstack)
   - Generates hardware attestations proving execution in genuine TEE
   - Protects cryptographic keys in hardware-encrypted memory
   - Uses `BS_BACKUP_ENCRYPTION_KEY_HEX` for symmetric encryption of keyshares
   - Runs continuously (24/7) to maintain keyshares in memory
   - Keeps keyshares in memory only: does not persist to disk as encryption key would be lost on restart, and operator must not access it
   - Must re-fetch keyshares from MPC nodes after restart or power loss

5. **Blockchain Monitor**: Maintains current view of MPC contract state
   - Embedded NEAR light client to track contract state
   - Automatically detects events, e.g., migration initiations
   - Enables autonomous operation without operator intervention

6. **HTTP Server** (Optional): Operational monitoring and observability
   - Health checks for liveness/readiness probes
   - Prometheus-style metrics (keyshare freshness, backup success/failure rates)
   - Operator dashboards for status visibility

### Remaining Work

See [(#949)](https://github.com/near/mpc/issues/949)
- It is advised that the node operator grants access only to specific contract methods for the backup service and the node: [(#946)](https://github.com/near/mpc/issues/946)
- Consider making `TeeState` generic over the identifier type (e.g., `TeeState<T>` where `T` can be `NodeId` or `AccountId`). Currently, `TeeState` uses `NodeId` for MPC nodes (allowing multiple nodes per operator), but backup services need `AccountId` as the identifier (one per operator). A generic implementation would avoid code duplication while supporting both use cases.

**Hard Launch Implementation Tasks:**

*Phase 1: Standalone Application with Mocked Attestations*
- [ ] Create `BackupServiceDockerImageHash` type in primitives (separate from `MpcDockerImageHash`)
- [ ] Implement voting structures for backup service images (`BackupServiceCodeHashesVotes`, `AllowedBackupServiceDockerImageHashes`)
- [ ] Implement `allowed_backup_service_code_hashes()` and `allowed_backup_service_launcher_compose_hashes()` view methods
- [ ] Update `register_backup_service()` to accept and verify attestations using `TeeState` verification logic
- [ ] Develop backup service as standalone long-running application
- [ ] Implement contract monitoring and event detection in backup service
- [ ] Add backup service attestation refresh mechanism (before expiration)
- [ ] Implement automatic backup/recovery flows based on contract events
- [ ] Add comprehensive integration tests with mocked attestations

*Phase 2: TEE Migration*
- [ ] Port backup service to TEE runtime (TDX with dstack)
- [ ] Replace mocked attestations with real TEE attestations
- [ ] Add attestation validity check to the contract
- [ ] Implement Docker image hash validation for backup services
- [ ] Update contract to reject mocked attestations (enforce real TEE attestations)
- [ ] Add automatic cleanup of expired backup service attestations
- [ ] Add comprehensive integration tests for full TEE attestation flow
- [ ] Create monitoring dashboards for backup service health
- [ ] Document TEE deployment procedures
- [ ] Document backup service upgrade procedure (voting for new images)

> **Implementation Strategy**: Similar to MPC nodes, the backup service will first be developed as a standalone application that uses mocked attestations. This allows development and testing of the blockchain interface, contract monitoring, and automatic backup/recovery flows in a controlled environment. Once the core functionality is stable, the service can be migrated into a TEE with real attestations.

## Materials

https://nearone.slack.com/archives/C07UW93JVQ8/p1753830474083739
NIST SP 800-56A https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf - page 105 - 106

