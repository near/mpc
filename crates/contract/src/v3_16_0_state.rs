//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{
    CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, env, require,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    state::ProtocolContractState,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ContractUpdateVotes,
};

/// A stored proposal holds a whole contract binary, so the migration clears both maps.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ProposedUpdates {
    vote_by_participant: IterableMap<AccountId, UpdateId>,
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

impl ProposedUpdates {
    fn clear_storage(mut self) {
        self.vote_by_participant.clear();
        self.entries.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
struct UpdateId(u64);

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct UpdateEntry {
    update: Update,
    bytes_used: u128,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum Update {
    Contract(Vec<u8>),
    Config(Config),
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.16.0` contract still deserializes during migration.
///
/// This module reads the *current* [`ProtocolContractState`], so a bound added to a stored type
/// is also an upgrade gate: state the new type rejects cannot be migrated.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: Option<AccountId>,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        require!(
            matches!(old.protocol_state, ProtocolContractState::Running(_)),
            "Contract must be in running state when migrating."
        );
        old.proposed_updates.clear_storage();

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            config: old.config,
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id.unwrap_or_else(|| {
                env::panic_str(
                    "No TEE verifier is configured. Participants must vote one in via vote_tee_verifier_change before upgrading.",
                )
            }),
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
            contract_update_votes: ContractUpdateVotes::default(),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{ProposedUpdates, Update, UpdateEntry, UpdateId};
    use crate::storage_keys::StorageKey;
    use near_sdk::store::IterableMap;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{env, testing_env};

    #[test]
    fn proposed_updates__clear_storage__should_release_the_stored_proposals_and_votes() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let baseline = env::storage_usage();
        let mut proposals = ProposedUpdates {
            vote_by_participant: IterableMap::new(StorageKey::_DeprecatedProposedUpdatesVotesV2),
            entries: IterableMap::new(StorageKey::_DeprecatedProposedUpdatesEntriesV2),
            id: UpdateId(1),
        };
        proposals.entries.insert(
            UpdateId(0),
            UpdateEntry {
                update: Update::Contract(vec![7; 4096]),
                bytes_used: 4096,
            },
        );
        proposals
            .vote_by_participant
            .insert("alice.near".parse().unwrap(), UpdateId(0));
        proposals.entries.flush();
        proposals.vote_by_participant.flush();
        assert!(env::storage_usage() > baseline);

        // When
        proposals.clear_storage();

        // Then
        assert_eq!(env::storage_usage(), baseline);
    }
}
