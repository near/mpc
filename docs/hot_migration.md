# Background

HOT want to migrate their keyshares to our MPC network.

There are three challenges associated with this endeavor:
1. We need a way to add a domain by importing keyshares.
2. HOT uses a different authentication mechanism. While we look up the `predecessor_id` and derive the public key from that account, HOT has the notion of a _wallet_:
    1. A _wallet_ consits of a user generated public private ed25519 keypair;
    2. The MPC network uses the public key associated to the wallet to derive a public key owned by the MPC network
    3. For every wallet, a list of authorized accounts exists. Specifically, wallet to authorized accounts is a many-to-many mapping, meaning:
        1. A wallet can be controlled by multiple different user accounts.
        2. one user can control multiple wallets.
3. The key derivation mechanism used by HOT is at the moment unclear. Need to find documentation for that.


## Proposal


### Contract Changes

The authentication mechanism supported by HOT poses a challenge for our smart contract. For one, we currently don't need to worry about authentication at all, since the derived public key is tied to the account that signed the signature request. Currently, authentication is implicit. For HOT wallets, authentication is explicit due to the above described authentication mechanism.

Hence, it is imperative that we keep a strict separation between the domains used by HOT and the domains used by the rest of the MPC network. If we mix them, we might accidentally enable the spending of another users balance.

Therefore, we must add a new domain purpose to the contract:

From the foregin chain transaction doc:
```rust
pub enum DomainPurpose {
    Sign,
    ForeignTx,
    CKD,
}
```
we add Hot:
```rust
pub enum DomainPurpose {
    Sign,
    ForeignTx,
    CKD,
    Hot,
}
```

The authentication mechanism can be abstracted and handled by a separate contract. In that case, we could enforce that signature requests submitted for a `Hot` domain _must_ be sent by a specific, authentication contract (whose address, for the first iteration, can be hard-coded in the MPC contract).

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
    hot_domain: HotDomainsInfo,
}

pub struct HotDomainInfo {
    // the keys to import
    pub keys: [2](KeyEventId, PublicKeyExtended),
    // set of node that report to have concluded the keyshare migration
    pub import_confirmations: BTreeSet<NodeId>,
}

impl HotDomainInfo {
    // clears `import_confirmations`
    pub fn reset(&mut self) {
        self.import_confirmations.clear();
        let new_keys = increment_attempt_id(self.keys); // imaginary function. We increment the attempt id and store it as a new key.
        self.keys = new_keys;
    }

    /// node calls this endpoints after they imported HOT's keyshare and stored it to the temporary keystore
    // counts vote by `node_id` in case `node_id` has not yet voted and returns the vote set.
    // returns error in case `node_id` has already voted.
    pub fn vote_imported(&mut self, node_id: NodeId, pks: &[](KeyEventId, PublicKeyExtended)) -> anyhow::Result<&BTreeSet<NodeId>> {
        if self.import_confirmations.contains(node_id) {
            return Err("participant already submitted a vote");
        }
        if self.keys != pks {
            return Err("mismatch public keys");
        }
        self.import_confirmations.insert(node_id);
        Ok(&self.import_confirmations)
    }
}

impl MpcContract {
    /// during migration, we need to reserve the DomainIds
    fn migrate() {
        // reserve Hot DomainId and add to registry
    }

    fn confirm_hot_pk_imported(&mut self, pks: [2](KeyEventId, PublicKeyExtended)>) -> Result<> {
        let signer = env::signer_id();
        // verify that the signer is a participant
        let node_id = self.verify_participant(signer)?;
        let res = self.hot_domain.vote_imported(node_id, pks)?;
        if res == participants.node_ids() {
            // Option 1: here, we want to add a new contract state "KeyMigrationCheck", during which the nodes compute a challenge and check if they can use the imported keyshares. In case it succeeds, the contract adds the new keyset to the keyset and resumes running state. In case it fails, it calls `reset` and rsumes running state without adding keys to domain.
            self.enter_verify_domain_state(pks)


            // Option 2:
            // The challenge is resolved here, embedded in the running state. In this ase, we must change the coordinator stop_fn such that we restart in case the keyset changes between running states.
        
            // Option 3:
            // We immediately entere a resharing state and do a key refresh
        }
    }

    /// custom sign endpoint for Hot domains. Depending on how kdf works, we might be able to use the existing `sign`
    fn sign_hot_domain(&mut self, domain_id: DomainId, HotDomainArgs) -> Result<()> {
        // potentially custom kdf
    }
}

```


### Node behavior
The node monitors the `HotDomainsInfo` contract state. In case it hasn't voted `confirm_hot_pk_imported` yet, it scans the current filesystem for keyshares belonging to the HOT Wallet.
In case it finds a share, it stores it to the temporary keystore and submits a vote to the contract for concluding the import.


Option 1:
In the coordinator, we add a new contract state `ConfirmKeyMigration`, during which the nodes resolve a simple challenge to check whether they can compute a result.

Option 2:
Node continues to monitor the `HotDomainsInfo` in a separate thread. Once it sees that all partiicpants voted, they resolve a challenge individually.

Option 3:
We immediately entere a resharing state and do a key refresh

## Testing

we need a testing strategy

