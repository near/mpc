# Background

HOT want to migrate their keyshares to our MPC network.

There are three challenges associated with this endeavor:
1. We need a way to add a domain by importing keyshares.
2. HOT uses a different authentication mechanism. While we look up the `predecessor_id` and derive the public key from that account, HOT has the notion of a _wallet_ [^1]:
    1. A _wallet_ consits of a user generated public private ed25519 keypair;
    2. The MPC network uses the public key associated to the wallet to derive a public key owned by the MPC network
    3. For every wallet, a list of authorized accounts exists. Specifically, wallet to authorized accounts is a many-to-many mapping, meaning:
        1. A wallet can be controlled by multiple different user accounts.
        2. one user can control multiple wallets.
3. The key derivation mechanism used by HOT is at the moment unclear. Need to find documentation for that.

[^1]: https://hot-labs.gitbook.io/hot-protocol/mpc-wallet/signature-generation-via-mpc/mpc-api

## Implementation Proposal

### Authentication Mechanism

The authentication mechanism supported by HOT poses a challenge for our smart contract. For one, we currently don't need to worry about authentication at all, since the derived public key is tied to the account that signed the signature request. Currently, authentication is implicit. For HOT wallets, authentication is explicit due to the above described authentication mechanism.

We will abstract the explicit authentication mechanism and assume the existence of a **hot-authorization smart-contract** that is authorized to request signatures for **any** wallet. This smart contract will only be able to request signatures for the keys imported from HOT. I.e. we preserve the existing implicit authentication mechanism for existing and future keys managed by the MPC network.

To be explicit: **It is responsiblity of the hot-authorization smart contract to authorize signature requests. The MPC smart contract will process any request it receives that stems from the HOT smart-contract**.

_Action Point:_
_- Lets schedule an audit to assess the safety of this and ensure we don't accidentally compromise existing keys._

### Key derivation

HOT seems to be using the same key derivation method as NEAR, so we don't expect any difficulties on that end (with the exception that their `tweak` corresponds to a uid relatedto the `walled_id` discussed above).

HOT:
```rust
/// Derives a public key from a tweak and a master public key by computing PK + [tweak] G
pub fn derive_public_key(public_key: AffinePoint, tweak: Scalar) -> AffinePoint {
    (AffinePoint::GENERATOR * tweak + public_key).to_affine()
}
```

us:
```rust
/// Derives the verifying key as X + tweak . G
pub fn derive_verifying_key(&self, public_key: &VerifyingKey<C>) -> VerifyingKey<C> {
    let derived_share = public_key.to_element() + C::Group::generator() * self.value();
    VerifyingKey::new(derived_share)
}
```

### Keyshare Import

We will need to import keyshares. We will assume that HOT can provide one valid keyshare for each of our production nodes and that the threshold matches our production threshold. Import will be coordinated by the contract and it will consist of thee stages:

1. Import preparation:
    - Nodes monitor the file system for the existence of keyshares from HOT in a specific directory.
    - Nodes query the contract to get the current `KeyEventId` for this import.
    - Nodes validate and write the HOT keyshares to their temporary keyshare storage (under the `keyEventId` handle).
    - Nodes confirm to the contract that they prepared the key import.
2. Keyshare validation:
    - Nodes test if they can generate a valid signature request for the newly imported keyshares.
    - Nodes test if they can run a key refresh with the newly imported keyshares.
    - Nodes confirm that validation succeeded to the contract or abort the import.
3. Adding keyshares to keyset:
    - Once the last node confirmed successful validation of the keyshares, the contract enters a resharing state and operations resume normally.
    This step ensures that the keyshares are loaded to permanent keyshare storage.

## Implementation Outline

We don't expect to be migrating any other keyshares. We aim for a design that can be easily removed after having concluded the keyshare migration.

### Contract Implementation

#### MpcContract changes

The contract will need extra state.

```rust
#[near_bindgen]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: dtos::ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
    // below is new
    hot_domain_migration_state: HotDomainMigrationState,
}
```

It will also require a dedicated sign and respond endpoint:

```rust

/// new sign / respond endpoints for the HOT key domain
impl MpcContract {
    /// custom sign endpoint for Hot domains. Depending on how kdf works, we might be able to use the existing `sign`
    pub fn sign_hot_domain(&mut self, args: HotDomainArgs) -> Result<()> {
        // potentially custom kdf
    }

    /// custom respond endpoint (if requried)
    pub fn respond_hot_domain(&mut self, response: HotDomainResponse) -> Result<()>;
}
```

and the migration and `vote_new_parameters` methods need to be altered:
```rust
/// existing method requiring modifications
impl MpcContract {
    /// during migration, we need to reserve the DomainIds
    pub fn migrate() {
        // reserve Hot DomainId and add to DomainRegistry
        // intialize HotDomainMigrationState
    }
    
    pub fn vote_pk() {
        // in case we entered an initializing state, we should ensure to reset the HotDomainMigration state and reserve a new domain id before resuming running state. That is due to some impliciti assumptions in our low-level, c.f. [#1234](https://github.com/near/mpc/issues/1234).
    }

    pub fn vote_reshared() {
        // in case we entered a resharing state, we should ensure to reset the HotDomainMigration state and increment the epoch id. Otherwise we will have an epoch_id mismatch in the KeyshareStorage.
    }
}
```

Additionally, it will need some endpoints to coordinate the keyshare import logic:
```rust
/// Methods for keyshare migration. For all of these, we need to ensure:
///     - that we are in a running state
///     - ensure the KeyEventId is compatible with the current contract state:
///          - EpochId must match
///          - DomainId must be the last added domain and correspond to a HOT domain
///     - the signer is authorized to vote
///     we refer to these as `can_import_hot_checks`
impl MpcContract {
    /// node calls this endpoint to confirm they stored the keyshares to the temporary keyshare storage
    pub fn hot_migration_confirm_prepared(&mut self, pks: [(KeyEventId, PublicKeyExtended); 2] -> Result<()> {
        // passes the vote down to the `HotDomainMigrationState` struct after passing `can_import_hot_checks`
    };
    // concludes the sign_valiation step
    pub fn hot_migration_conclude_sign_validation(&mut self, response: HotDomainResponse) -> Result<()> {
        // passes the vote down to the `HotDomainMigrationState` struct after verifying the signer is authorized to respond.
    }
    // starts the key refresh validation
    pub fn hot_migration_start_key_refresh(&mut self, key_event_id: KeyEventId) -> Result<()> {
        // passes the vote down to the `HotDomainMigrationState` struct after passing `can_import_hot_checks`
    }
    // votes to conclude the key refresh validation. Upon receiving the last vote, the contract enters a resharing state.
    pub fn hot_migration_conclude_key_refresh(&mut self, key_event_id: KeyEventId) -> Result<()> {
        // passes the vote down to the `HotDomainMigrationState` struct after passing `can_import_hot_checks`
        // if this concludes the migration, then the contract adds the refreshed key to the Keyset of the current running state.
    }
    /// resets the HotDomainMigrationState, such that a new import attempt can be started
    pub fn hot_migration_new_attempt() {
        // authenticates the signer
        // allows to re-attempt import with a new attempt id (e.g., if the previous attempt was unsuccessful due to invalid keyshares)
    }
}
```

#### HotDomainMigrationState struct

The `HotDomainMigrationState` is used to coordinate the keyshare import between the nodes

```rust
pub enum HotDomainMigrationState {
    PrepareImport(HotDomainPrepareImportState),
    Validation(HotDomainValidationState),
    // the imported keyshares
    Imported([(KeyEventId, PublicKeyExtended); 2]),
}

impl HotDomainMigrationState {
    fn reset(&mut self, current_epoch: EpochId, publicKeys: [(DomainId, PublicKeyExtended); 2]) {
        // if self is not Imported, then we reset to PrepareImport with the given epoch and domain id (set attempt to 0)
    }
}

/* Prepare import state and logic */
pub struct HotDomainPrepareImportState {
    // the keys to import
    // Note: same epoch as the one we are currently in. Attempt Id set to 0 initially.
    pub keys_to_import: [(KeyEventId, PublicKeyExtended); 2],
    // set of nodes that report to have prepared the keyshare migration
    pub import_prepared: BTreeSet<NodeId>,
}


/* Validation state and logic */
pub struct HotDomainValidationState {
    // the keys to validate (of attempt_id 0)
    pub keys_to_validate: [(KeyEventId, PublicKeyExtended); 2],
    // set of node that report to have prepared the keyshare migration
    pub task: HotDomainVaidationTask,
}

pub struct HotDomainValidationTask {
    Sign(SignTask),
    KeyReshare(ResharingTask),
}

struct SignTask {
    // make this same as what is used in the `sign_hot_domain` method 
    pub pending_sign_request: HotSignRequest;
}

impl SignTask {
    /// validates the response and returns Ok(()) in case of success
    pub fn validate_sign_response(resp: HotSignResponse) -> Result<()> {
        // call the validation logic that would be used in the main response method
    }
}

struct ResharingTask {
    reshared_keys: Vec<KeyForDomain>,
    resharing_key: KeyEvent, 
}
```

Note about Domains: from the foregin chain transaction doc, we have the following
```rust
pub enum DomainPurpose {
    Sign,
    ForeignTx,
    CKD,
}
```
we can simply add Hot:
```rust
pub enum DomainPurpose {
    Sign,
    ForeignTx,
    CKD,
    Hot,
}
```

#### Methods

WIP - note that we keep the epoch_id the same for the key refresh. This is an excption. We will use the attempt_id to distinguish the different keys.
```rust

/// new sign / respond endpoints for the HOT key domain
impl MpcContract {
    /// custom sign endpoint for Hot domains. Depending on how kdf works, we might be able to use the existing `sign`
    pub fn sign_hot_domain(&mut self, args: HotDomainArgs) -> Result<()> {
        // potentially custom kdf
    }

    /// custom respond endpoint (if requried)
    pub fn respond_hot_domain(&mut self, response: HotDomainResponse) -> Result<()>;
}

/// existing method requiring modifications
impl MpcContract {
    /// during migration, we need to reserve the DomainIds
    pub fn migrate() {
        // reserve Hot DomainId and add to registry
    }

    pub fn vote_new_parameters() {
        // we should probably dis-allow resharings until the hot-domain is imported.
        // it's not great, but seems simplest.
        // alternatively, we can reset and increment the epoch id in the hot key migration, but we need to make sure we test this.
        // The issue here is that we have some implicit assumptions about the order of keys in Keyset and we need to ensure we can have a Keyset that does not contain all keys of the current DomainRegistry.
    }
}

/// Methods for keyshare migration. For all of these, we need to ensue that we are in a running state
impl MpcContract {
    /// node calls this endpoint to confirm they stored the keyshares to the temporary keyshare storage
    pub fn hot_migration_confirm_prepared(&mut self, pks: [(KeyEventId, PublicKeyExtended); 2] -> Result<()>;
    // concludes the sign_valiation step
    pub fn hot_migration_conclude_sign_validation(&mut self, response: HotDomainResponse) -> Result<()>;
    // starts the key refresh validation
    pub fn hot_migration_start_key_refresh(&mut self, key_event_id: KeyEventId) -> Result<()>;
    // votes to conclude the key refresh validation. Upon receiving the last vote, the contract enters a resharing state.
    pub fn hot_migration_conclude_key_refresh(&mut self, key_event_id: KeyEventId) -> Result<()>;
    // to reset hot migration
    pub fn hot_migration_reset(&mut self);
}
```

Some helper functions on the lower level. Note that we could probably implement a lot of this on the higher level. This is WIP.
```rust


impl HotDomainPrepareImportState {
    // clears `import_prepared`
    pub fn reset(&mut self) {
        self.import_confirmations.clear();
        let new_keys = increment_attempt_id(self.keys_to_import); // We increment the attempt id and store it as a new key.
        self.keys_to_import = new_keys;
    }

    /// node calls this endpoints after they stored HOT's keyshare in the temporary keystore.
    /// returns the set of nodes that have confirmed to have concluded this step.
    /// returns error in case `node_id` has already voted or in case the public key or key event id does not match.
    pub fn import_prepared(&mut self, node_id: NodeId, pks: &[](KeyEventId, PublicKeyExtended)) -> anyhow::Result<&BTreeSet<NodeId>> {
        if self.import_confirmations.contains(node_id) {
            return Err("participant already submitted a vote");
        }
        if self.keys_to_import != pks {
            return Err("mismatch keys or key event");
        }
        self.import_confirmations.insert(node_id);
        Ok(&self.import_confirmations)
    }
}

impl HotDomainValidationState {
    pub fn validate_sign_response(&mut self, response: HotSignResponse, params: &ThresholdParameters) -> anyhow::Result<()> {
        let HotDomainValidationTask::Sign(sign_task) = self.task else {
            anyhow::bail!("Expected sign task");
        };
        sign_task.validate_sign_response(response)
        match sign_task.validate_sign_response(response) {
            Err(err) => // report error and fail,
            Ok(_) => {
                self.task = HotDomainVaidationTask::KeyReshare(ReshareValidationTask::new(self.keys_to_validate, params));
            }
        }
        Ok(())
    }

    pub fn start_key_resharing(&mut self, key_event_id: KeyEventId) -> anyhow::Result<()> {
        let HotDomainValidationTask::Resharing(resharing_task) = self.task else {
            anyhow::bail!("expected sign task");
        };
        resharing_task.key_event.start(key_event_id, KEY_EVENT_TIMEOUT_BLOCKS)
    }

    // returns the reshared keys in case of success
    pub fn validate_key_resharing(
        &mut self,
        key_event_id: KeyEventId,
    ) -> Result<Option<[(KeyEventId, PublicKeyExtended); 2]>> {
        let HotDomainValidationTask::Resharing(resharing_task) = self.task else {
            anyhow::bail!("expected sign task");
        };
        let previous_key = self.keys_to_validate[resharing_task.reshared_keys.len()].1.clone();

        if resharing_task
            .resharing_key
            .vote_success(&key_event_id, previous_key.key.clone())?
        {
            let new_key = KeyForDomain {
                domain_id: key_event_id.domain_id,
                attempt: key_event_id.attempt_id,
                key: previous_key.key,
            };
            resharing_task.reshared_keys.push(new_key);
            
            // if there is another resharing to do, then update `resharing_task.resharing_key`
            if resharing_task.reshared_keys.len() < 2 {
                // note: EpochId Handling is tricky
                resharing_task.resharing_key = KeyEvent{...};
                Ok(None)
            } else {
                // else, update self:
                to_return = resharing_task.reshared_keys.into();
                Ok(to_return)
            }
        } else {
            Ok(None)
        }
    }

    pub fn reset(&mut self) {
        self = HotDomainMigrationState::PrepareImport(...)
    }
}

```


### Node Implementation

We can add a `MigratingHotState` in the `ContractRunningState` of the nodes [indexer](https://github.com/near/mpc/blob/f1b0d197ea29767acc6ed4631f35e2cc4901b61e/crates/node/src/indexer/participants.rs#L106C12-L106C32). We spawn a separate task for monitoring the filesysem, importing keyshares and engaging with the system.
Similar to how we multiplex for the resharing state, we can multiplex for the HOT migration and ue the same p2p mesh network that is used by the running state (fine, since it's just a key refres).
    
## Testing

we need a testing strategy

## Open Qustions

- can we have a mismatch between Keyset and DomainRegistry?
