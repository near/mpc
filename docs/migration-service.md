# Migration Service

## Overview

Near One is currently in the process of migrating the MPC nodes into a **Trusted Execution Environment (TEEs)** (c.f. [TEE doc](docs/securing_mpc_with_tee_design_doc.md) for an introduction to TEEs and their benefits).

Running MPC nodes inside TEEs significantly increases the security of the network, but poses additional operational challenges:

- **Node migrations become more difficult:** Once an MPC node operates inside a TEE, extracting or transferring its secret key shares is infeasible. Migrating a node would normally require a full resharing, involving the entire MPC network.  
- **Recovery from catastrophic failures is harder:** If multiple MPC nodes fails irrecoverably and simultaneusly, the network risks losing its signing quorum, which could halt protocol operations.

This document outlines the design and implementation of a **Migration Service**, a service aimed at addressing those issues by solving above problems:

1. **Operational resilience** — the migration service enables secure recovery of nodes in the event of hardware or system failure.  
2. **Node migration** — the migration service allows node operators to move their MPC nodes into or between TEEs without resharing.

Near-One will roll-out its TEE implementation in two phases:
- **Soft Launch:**
    - Some MPC nodes are running within TEEs.
    - Their key shares are backed-up outside of the TEE through the Migration Service.
    - The MPC contract does not formally enforce nodes to run inside a TEE.
    - The migration service is used to move nodes into TEEs.
- **Hard Launch:** 
    - All MPC nodes are running within TEEs.
    - Their key shares are backed-up inside another TEE through the Migration Service.
    - The MPC contract kicks out any nodes that are not running inside a TEE.
    - The migration service is used to move nodes between different TEEs (if required).

## Migration Service Design

### System Components

The Migration Service enables secure backup and recovery of MPC node key shares. It involves four main components:
- **MPC Node**
  Runs the Multi-Party Computation protocol and holds the node’s secret key shares.  
- **Node Operator** 
  A person or entity responsible for an MPC node.
- **Backup Service**
  A separate process, running on a different machine than the MPC node. The backup service stores the encrypted key shares from the MPC node.
  During the *soft launch*, this service is implemented as a simple CLI and manually triggered by the node operator.
  For the *hard launch*, it will be a long-running program inside its own TEE, maintain an up-to-date view of the on-chain MPC contract and handle back-up and recovery processes in an automated manner. Each node operator must run their own back-up service.
- **MPC Smart Contract**
  Serves as the source of truth for protocol state and node information.  
  It stores metadata about registered backup services and information about node migrations.

Communication between the backup service and the MPC node takes place over **mutual TLS**. The MPC smart-contract, (i.e. the NEAR blockchain) is used as a public key infrastructure, that is, the MPC node and the backup service fetch the expected public key from the smart contract and authenticate their peer against the expected value.
To protect against spoofing attacks, sensitive data is additonally encrypted via AES 256.

### Workflows

On a high-level, the migration service allows two workflows:
- _Back-up_: securely back-up and store their secret shares in an external environment;
- _Recovery/Migration_: securely request the backed-up secret shares from the external environment and import them into a new node.

Note that the migration service does not enable a _"Recovery"_ of the _entire_
node, but only of the secret shares. The MPC node generates a few secrets that would still be unrecoverable, since no back-up exists (such as TLS keys or access keys for NEAR accounts). As such, _Recovery_ is just a special case of _Migration_, where the target host machine stays the same. TLS Key and access key of the node are still expected to change.


#### Backup 

##### Soft Launch

1. The node operator calls `register_backup_service()` to register the backup service's public key in the smart contract. The node, running a NEAR client, has access to this ifnormation and uses it for the authentication in the following step.
2. The node operator manually runs `backup-cli get-keyshares` with the MPC node's URL, public key and the symmetric AES-256 key (matching `MPC_BACKUP_ENCRYPTION_KEY_HEX` below) as input. This triggres the following:
    - The `backup-cli` and MPC node establish a mutually authenticated TLS connection using their P2P keys.
    - The `backup-cli` requests the keyshares from the MPC node's `GET /get_keyshares` endpoint
    - The MPC node returns the AES-256 encrypted keyshares. The MPC node uses the node-operator provided symmetric key `MPC_BACKUP_ENCRYPTION_KEY_HEX` for encryption.
    - The `backup-cli` saves the encrypted keyshares to local storage

> **Note**: For soft launch, the operator must manually trigger the backup using the `backup-cli` tool. There is no automatic periodic backup.

```mermaid
---
title: Backup Flow (Soft Launch)
---
flowchart TD
    SC("
      **Smart Contract**
      _Source of truth for
      protocol state and
      node information._
    ");

    MPC("
      **MPC Node**
      _Currently participating in the MPC network.
      Holds sensitive key shares_.
    ");

    BS("
      **Backup Service**
      _Stores encrypted backups
      of key shares.
      Uniquely identified by a public key._
    ");

    NO("
      **Node Operator**
      _Owner of the MPC node and Backup Service._
    ");
    
    NO -->|Provides symmetric encryption key| BS;
    NO -->|Provides symmetric encryption key| MPC;
    NO -->|1\. register backup service in smart contract| SC;
    BS -->|2\. read MPC node Public Key and address| SC;
    BS --> |3\. request encrypted key shares (mTLS + AES 256)| MPC;
    MPC -->|4\. read backup service Public Key | SC;
    MPC -->|5\. send encrypted key shares | BS;
    NO@{ shape: manual-input}
    SC@{ shape: db}
    BS@{ shape: proc}
    MPC@{ shape: proc}
```


##### Hard Launch
For the hard-launch, above steps will not be run manually, but automatically:
- the backup service runs a NEAR node and monitors the MPC smart contract;
- the backup service compares the keyshares it has possession of with the key shares it is supposed to have possession of;
- in case the backup service is missing key shares, it goes through steps 2a-2d above.
Additionally, the MPC node will have to verify the attestation submitted by the backup-service.

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

##### Soft Launch

1. The node operator calls `start_node_migration()` with the new node's `ParticipantInfo` in the smart contract
2. The node operator manually runs `backup-cli put-keyshares` with the MPC node's URL, public key and the symmetric AES-256 key (matching `MPC_BACKUP_ENCRYPTION_KEY_HEX` below) as input. This triggres the following:
    - The `backup-cli` and MPC node establish a mutually authenticated TLS connection using their P2P keys.
    - The `backup-cli` submits the AES-256 encrypted keyshares over the TLS connection to the nodes `PUT /set_keyshares` endpiont.
    - The node encrypts the received keyshares with PUT `MPC_BACKUP_ENCRYPTION_KEY_HEX`
    - The new node calls `conclude_node_migration()` to finalize the migration

> **Note**: For soft launch, the operator must manually trigger the keyshare transfer using the `backup-cli` tool. There is no automatic contract monitoring.

```mermaid
---
title: Recovery Flow (Soft Launch)
---
flowchart TD
    NO["**Node Operator**
      _Owner of the MPC node and Backup Service._"]

    SC["**Smart Contract**
      _Source of truth for
      protocol state and
      node information._"]

    BS@{ label: "**Backup Service**
        _Stores encrypted backups of key shares. 
        Uniquely identified by a public key._" }
    MPC["**New MPC node**
      _Needs keyshares from backup service._"]
    
    NO -->|Provides symmetric encryption key| BS;
    NO -->|Provides symmetric encryption key| MPC;
    NO -- "1\. start onboarding for new node in smart contract" --> SC
    BS -- "2\. read MPC node Public Key and address" --> SC
    BS -- "3\. send encrypted key shares" --> MPC
    MPC -- "4\. resolve recovery and participate in the network" --> SC

    NO@{ shape: manual-input}
    SC@{ shape: db}
    BS@{ shape: proc}
    MPC@{ shape: proc}
```

##### Hard Launch

For the hard launch, the recovery flow is the same as in the soft launch, but more automated: the backup service monitors the contract state and initiates migrations automatically (e.g., by calling `conclude_node_migration`). The operator only needs to initiate the process by calling `start_node_migration`.

There’s also an additional TEE-attestation step: the new node must verify the backup service’s attestation before saving the received keyshares, and the contract must verify the backup service’s attestation before handing over the public key and address of the new MPC node.

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

### Operational Details and Constraints

For security reasons and to avoid edge cases and race conditions, the MPC network allows migration of nodes only while the protocol is in a `Running` state (as opposed to `Resharing` or `Initializing`, which are the two other well-defined states).

Note that starting a migration workflow does not require a signing quorum. Instead, each participant can migrate their node at their own discretion. However, to avoid making the migration process a DoS attack vector, protocol state changes must have priority over any ongoing migrations.
If the protocol state changes into a `Resharing` or `Initializing` state, any ongoing migration processes will simply be cancelled.


## Implementation Details

### Node

#### Node behavior

A node must only participate in the MPC protocol if it is in the set of active participants of the current running or resharing epoch. For this, the TLS key of a node acts as a unique identifier _(implemented in [(#1032)](https://github.com/near/mpc/pull/1032/files#diff-c54adafe6cebf73c37af97ce573a28c60593be635aa568ec93e912b8f286aa83R181))_.

Currently, due to limitations of our implementation, nodes need to drop and re-establish all connections in case of a change in the participant set. Before adding the migration feature, this was only possible if the epoch id changed, which happened only during a protocol state change.
Now, nodes need to be able to recognize and re-establish a connection if the participant set changes without an epoch incrementing _(implemented in [(#1061)](https://github.com/near/mpc/pull/1061) and [(#1032)](https://github.com/near/mpc/pull/1032/))_.

Additionally, nodes need to remove any triples and pre-signatures involving the node that was removed from the participant set in the migration process _(implemented in [(#1032)](https://github.com/near/mpc/pull/1032/))_.

#### Web Endpoints

The **MPC node** exposes web endpoints over which the backup service can submit requests. These endpoints require mutual TLS authentication using the published P2P keys.

The exposed endpoints are:
- **GET /get_keyshares** - Returns the encrypted keyshares if a valid backup service is registered in the contract.
- **PUT /set_keyshares** - Accepts encrypted keyshares from the backup service to restore a recovering node.

### Contract

The contract stores migration-related information in the `NodeMigrations` struct:

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

> **Hard Launch Extension (Planned):** `BackupServiceInfo` will be extended with `attestation: Option<Attestation>` and `registered_at: Timestamp` fields for TEE attestation verification and expiration tracking.

**Hard Launch Extensions:**

For hard launch, the backup service must provide TEE attestation similar to MPC nodes. The contract will need to be extended to support attestation verification for backup services.

**Planned Implementation Approach:**

The backup service identification remains the same as soft launch: `AccountId` maps to `BackupServiceInfo`. For hard launch, the `BackupServiceInfo` struct would be extended to include attestation:

```Rust
/// Backup service authentication information (PLANNED extension for hard launch)
pub struct BackupServiceInfo {
    /// Ed25519 public key for mutual TLS authentication
    pub public_key: Ed25519PublicKey,
    
    /// TEE attestation proving backup service runs approved code (hard launch only)
    pub attestation: Option<Attestation>,
    
    /// Timestamp when backup service registered (for attestation expiration tracking)
    pub registered_at: Option<Timestamp>,
}
```

The backup service attestation verification would follow the same process as MPC node attestations:
1. Backup service generates TLS keypair inside TEE
2. Creates `ReportData` V1: `[version(2 bytes) || SHA3-384(tls_public_key) || padding]`
   - Note: Unlike MPC nodes, backup services don't include an `account_public_key` since they don't sign transactions
3. Obtains TEE quote embedding the `ReportData`
4. Submits attestation via `register_backup_service(public_key, attestation)`
5. Contract verifies:
   - Quote validity via attestation provider
   - Docker image hash against allowed list
   - Launcher compose hash (if applicable)
   - Timestamp within deadline
   - `ReportData` matches SHA3-384 hash of the submitted `tls_public_key`
6. Contract stores attestation in `backup_services_info[AccountId].attestation`

> **Note**: Unlike MPC nodes which may need multiple attestations per operator, backup services use a simpler one-per-operator model. The `AccountId` remains the unique identifier, consistent with soft launch.

#### Migration Methods

The contract provides the following methods:

- **`start_node_migration(destination_node_info: ParticipantInfo)`** - Initiates a node migration:
    - Called by the node operator
    - Creates an `OngoingNodeMigration` record for the given `AccountId`
    - Stores the destination node's `ParticipantInfo` (new TLS keys, etc.)
    - Returns an error if the protocol is not in `Running` state
    - Returns an error if caller is not a current participant

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

> **Hard Launch Extension (Planned):** For hard launch, `register_backup_service()` will require an `attestation` parameter and perform TEE verification similar to MPC nodes. The contract will verify the attestation validity, Docker image hash, and store the attestation before allowing backup operations. Backup services will need to refresh attestations before expiration.

#### Migration Related Behavior

- The `OngoingNodeMigration` records are automatically cleared when the protocol transitions from `Running` state to `Resharing` or `Initializing` state, effectively cancelling any in-progress migrations.
- **Future Enhancement**: It may be desirable for the contract to verify that calls to `conclude_node_migration()` come from the actual onboarding node by checking the transaction signer's public key _(see [(#1086)](https://github.com/near/mpc/issues/1086))_. This would prevent ill-behaved decommissioned nodes from making spurious migration calls. This would require:
    - Comparing `env::signer_account_pk()` with the public key associated with the participant (note: this is different from the TLS key currently stored as [`signer_pk`](https://github.com/near/mpc/blob/b5a9d1b2eef4de47d19b66cb25b577da2b897560/crates/contract/src/tee/tee_state.rs#L32) in TEEState)
    - Adding this public key to the `ParticipantInfo` struct
    - Including this public key in the TEE attestation


### Backup Service

#### Soft Launch Implementation

For the soft launch, the node operator and a few scripts (`backup-cli`) will act as the backup service. The operator runs these scripts manually on their own infrastructure.

#### Hard Launch Implementation

For hard launch, the backup service is a standalone long-running application inside its own TEE, physically separate from any MPC node TEE.

**Architecture Requirements:**
1. **TEE Execution**: Runs in TDX.
2. **Attestation Generation**: Generates and refreshes TEE attestations.
3. **Contract Monitoring**: Maintains current view of MPC smart contract state.
4. **Event Processing**: Monitors for migration events (`start_node_migration` calls).
5. **HTTP Server**: Exposes endpoints for health checks and metrics (optional).

**Operational Characteristics:**
- **Always Running**: Unlike the soft-launch scripts, the hard-launch backup service runs 24/7. All backed-up keyshares are kept in memory only (not on disk), so it needs to re-fetch the secret shares after recovering, e.g. after a power loss.
- **Automatic Response**: Detects migration events and initiates keyshare transfer without operator intervention.
- **Attestation Refresh**: Periodically refreshes TEE attestation before expiration.
- **Monitoring**: Provides health status and operation logs for operators.

**Security Properties:**
- **TEE Isolation**: Backup service code and memory protected by hardware.
- **Attestation Proof**: Contract cryptographically verifies correct execution.
- **No Operator Access**: Node operator cannot access decrypted keyshares.
- **Forward Secrecy**: Ephemeral keys ensure past sessions remain secure even if current keys compromised.
- **Docker Image Verification**: Contract ensures only approved backup service code executes.

### Node Operator

Node operators are responsible for:
1. **Registering Backup Service**: Call `register_backup_service()` to store the backup service's public key in the contract
2. **Initiating Migration**: Call `start_node_migration()` with the new node's `ParticipantInfo` when migrating to new hardware
3. **Running Backup Service** (Soft Launch): Execute `backup-cli` scripts to backup and restore keyshares during migrations
4. **Managing Environment Variables** (Soft Launch): Ensure `MPC_BACKUP_ENCRYPTION_KEY_HEX` is consistently set on both MPC node and backup-cli

> **Hard Launch**: In hard launch, the backup service runs autonomously in a TEE and requires no manual intervention from operators beyond initial registration.



### Todo
See [(#949)](https://github.com/near/mpc/issues/949)
- It is advised that the node operator grants access only to specific contract methods for the backup service and the node: [(#946)](https://github.com/near/mpc/issues/946)

**Hard Launch Implementation Tasks:**
- [ ] Add `attestation` parameter to `register_backup_service()` contract method
- [ ] Implement attestation verification for backup services in contract
- [ ] Store attestation with expiration tracking in contract
- [ ] Add attestation validity check in MPC node before backup/recovery operations
- [ ] Develop backup service as long-running TEE application
- [ ] Implement contract monitoring and event detection in backup service
- [ ] Add backup service attestation refresh mechanism (before expiration)
- [ ] Implement Docker image hash validation for backup services
- [ ] Add automatic cleanup of expired backup service attestations
- [ ] Add comprehensive integration tests for attestation flow
- [ ] Document backup service deployment procedures
- [ ] Create monitoring dashboards for backup service health

## Materials:
https://nearone.slack.com/archives/C07UW93JVQ8/p1753830474083739
NIST SP 800-56A https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf - page 105 - 106

