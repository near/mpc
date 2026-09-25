//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{
    CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, env,
    store::{IterableMap, Lazy, LookupMap},
};
use std::collections::BTreeSet;

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{key_state::AuthenticatedParticipantId, votes::Votes},
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::{
        measurements::{AllowedMeasurements, MeasurementVotes},
        proposal::{
            AllowedLauncherImages, LauncherHashVotes, NodeImageHash, StoredDockerImageHashes,
        },
        tee_state::{NodeAttestation, TeeState},
        verifier_votes::TeeVerifierVotes,
    },
    update::ContractUpdateVotes,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldCodeHashesVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, NodeImageHash>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: OldCodeHashesVotes,
    launcher_votes: LauncherHashVotes,
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, NodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: MeasurementVotes,
}

impl From<OldTeeState> for TeeState {
    fn from(old: OldTeeState) -> Self {
        // Pending code-hash votes are dropped. We don't need to optimize for this and it's not
        // worth the review & testing effort.
        TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: Votes::new(
                StorageKey::CodeHashVotesByVoter,
                StorageKey::CodeHashVotesByProposal,
            ),
            launcher_votes: old.launcher_votes,
            stored_attestations: old.stored_attestations,
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        }
    }
}

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
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.15.1` contract still deserializes during migration.
///
/// This module reads the *current* [`ProtocolContractState`], so a bound added to a stored type
/// is also an upgrade gate: state the new type rejects cannot be migrated. That is deliberate for
/// [`ParticipantUrl`](crate::primitives::participants::ParticipantUrl) — a url over the bound
/// fails [`crate::MpcContract::migrate`] and rolls the deploy back, rather than being silently
/// truncated. Check the participant set before deploying a change of that kind.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: OldSupportedForeignChainsByNode,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: Option<AccountId>,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }
        old.node_foreign_chain_support.clear_storage();
        old.proposed_updates.clear_storage();

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            contract_update_votes: ContractUpdateVotes::default(),
            config: old.config,
            tee_state: old.tee_state.into(),
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
        }
    }
}

/// Shadow of the `3.15.1` legacy account-keyed support map; the migration clears it.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldSupportedForeignChainsByNode {
    foreign_chain_support_by_node: IterableMap<dtos::AccountId, BTreeSet<dtos::ForeignChain>>,
}

impl OldSupportedForeignChainsByNode {
    fn clear_storage(mut self) {
        self.foreign_chain_support_by_node.clear();
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::storage_keys::StorageKey;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

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

    #[test]
    fn old_supported_foreign_chains_by_node__clear_storage__should_release_all_entries() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let baseline = env::storage_usage();
        let mut legacy = OldSupportedForeignChainsByNode {
            foreign_chain_support_by_node: IterableMap::new(
                StorageKey::_DeprecatedSupportedForeignChainsByNode,
            ),
        };
        legacy.foreign_chain_support_by_node.insert(
            "alice.near".parse().unwrap(),
            BTreeSet::from([dtos::ForeignChain::Bitcoin]),
        );
        legacy.foreign_chain_support_by_node.insert(
            "bob.near".parse().unwrap(),
            BTreeSet::from([dtos::ForeignChain::Solana]),
        );
        legacy.foreign_chain_support_by_node.flush();
        assert!(env::storage_usage() > baseline);

        // When
        legacy.clear_storage();

        // Then
        assert_eq!(env::storage_usage(), baseline);
    }
}
