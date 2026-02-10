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

At this point, it is unclear what exact key derivation mechanism HOT uses. We need to accound for the possibility that it might be different to ours and that signature payloads might be different.

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

Note:
- Keyshare validation will be the most annoying part to implement. It is unclear how to do this correctly at this point. We have two options:
    - re-use the established p2p mesh network and forward transactions related to the validation logic to the task spawning it
    - create a new p2p mesh network in parallel
    
    The latter might be our option of choice, as it would have us re-visit certain design decisions on the p2p layer that we intend to optimize either way. The former would be annoying, as any forwarding logic we implement now would have to be reverted afterwards?

    There is the option of trowing a hail-mary and _not_ validating keyshares before the final resharing, but that is borderline suicidal. We could also add a `ConfirmKeyMigration` Protocol state, but that is awfully specific and will also need to be reverted later.

## Implementation Outline

### Contract Changes

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
    hot_domain: HotDomainMigrationState,
}

pub enum HotDomainMigrationState {
    PrepareImport(HotDomainPrepareImportState),
    Validation(HotDomainValidationState),
    Imported,
}

pub struct HotDomainPrepareImportState {
    // the keys to import
    pub keys: [2](KeyEventId, PublicKeyExtended),
    // set of node that report to have prepared the keyshare migration
    pub import_prepared: BTreeSet<NodeId>,
}

impl HotDomainPrepareImportState {
    // clears `import_prepared`
    pub fn reset(&mut self) {
        self.import_confirmations.clear();
        let new_keys = increment_attempt_id(self.keys); // imaginary function. We increment the attempt id and store it as a new key.
        self.keys = new_keys;
    }

    /// node calls this endpoints after they stored HOT's keyshare in the temporary keystore.
    /// returns the set of nodes that have confirmed to have concluded this step.
    /// returns error in case `node_id` has already voted or in case the public key or key event id does not match.
    pub fn import_prepared(&mut self, node_id: NodeId, pks: &[](KeyEventId, PublicKeyExtended)) -> anyhow::Result<&BTreeSet<NodeId>> {
        if self.import_confirmations.contains(node_id) {
            return Err("participant already submitted a vote");
        }
        if self.keys != pks {
            return Err("mismatch keys or key event");
        }
        self.import_confirmations.insert(node_id);
        Ok(&self.import_confirmations)
    }
}

// todo
pub struct HotDomainValidationState {

}

impl HotDomainValidatoinState {
    pub fn start_sign_validatation(..);
    pub fn confirm_sign_validation(..);
    pub fn start_key_refresh(KeyEventId);
    pub fn conclude_key_refresh(KeyEventId);
}


impl MpcContract {
    /// custom sign endpoint for Hot domains. Depending on how kdf works, we might be able to use the existing `sign`
    fn sign_hot_domain(&mut self, domain_id: DomainId, HotDomainArgs) -> Result<()> {
        // potentially custom kdf
    }

    /// during migration, we need to reserve the DomainIds
    fn migrate() {
        // reserve Hot DomainId and add to registry
    }

    // below is for migrating and validating the keyshares
    fn confirm_hot_migration_prepared(&mut self, pks: [2](KeyEventId, PublicKeyExtended)>) -> Result<&BTreeSet<NodeId>> {
        let signer = env::signer_id();
        // verify that the signer is a participant
        let node_id = self.verify_participant(signer)?;
        let res = self.hot_domain.import_prepared(node_id, pks)?;
        if res == participants.node_ids() {
            // enter HotMigrationValidationState
        }
        Ok(res)
    }


    // todo
    pub fn start_sign_validatation(..);
    pub fn confirm_sign_validation(..);
    pub fn start_key_refresh(KeyEventId);
    pub fn conclude_key_refresh(KeyEventId);
    pub fn abort_validation(..);
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

The authentication mechanism can be abstracted and handled by a separate contract. In that case, we could enforce that signature requests submitted for a `Hot` domain _must_ be sent by a specific, authentication contract (whose address, for the first iteration, can be hard-coded in the MPC contract).


## Testing

we need a testing strategy

