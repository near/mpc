//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::Attestation;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
use near_sdk::{
    env,
    store::{IterableMap, LookupMap},
};
use std::collections::{BTreeSet, HashSet};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain, Keyset},
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
        votes::ThresholdParametersVotes,
    },
    state::key_event::KeyEvent,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes},
        tee_state::NodeId,
    },
    update::{Update, UpdateId},
};

// Old state types without foreign_chain_policy fields
// These match the v3.0.2 contract state layout

#[derive(Debug, BorshDeserialize)]
struct OldRunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: ThresholdParameters,
    pub parameters_votes: ThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
    // Note: foreign_chain_policy and foreign_chain_policy_votes were not present in v3.0.2
}

#[derive(Debug, BorshDeserialize)]
struct OldInitializingContractState {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: KeyEvent,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
    // Note: foreign_chain_policy was not present in v3.0.2
}

#[derive(Debug, BorshDeserialize)]
struct OldResharingContractState {
    pub previous_running_state: OldRunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
}

#[derive(Debug, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(OldInitializingContractState),
    Running(OldRunningContractState),
    Resharing(OldResharingContractState),
}

impl From<OldRunningContractState> for crate::state::running::RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        crate::state::running::RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters,
            parameters_votes: old.parameters_votes,
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
            // Initialize with empty policy - nodes will vote for initial policy
            foreign_chain_policy: Default::default(),
            foreign_chain_policy_votes: Default::default(),
        }
    }
}

impl From<OldInitializingContractState> for crate::state::initializing::InitializingContractState {
    fn from(old: OldInitializingContractState) -> Self {
        crate::state::initializing::InitializingContractState {
            domains: old.domains,
            epoch_id: old.epoch_id,
            generated_keys: old.generated_keys,
            generating_key: old.generating_key,
            cancel_votes: old.cancel_votes,
            // Initialize with empty policy
            foreign_chain_policy: Default::default(),
        }
    }
}

impl From<OldResharingContractState> for crate::state::resharing::ResharingContractState {
    fn from(old: OldResharingContractState) -> Self {
        crate::state::resharing::ResharingContractState {
            previous_running_state: old.previous_running_state.into(),
            reshared_keys: old.reshared_keys,
            resharing_key: old.resharing_key,
            cancellation_requests: old.cancellation_requests,
        }
    }
}

impl From<OldProtocolContractState> for crate::state::ProtocolContractState {
    fn from(old: OldProtocolContractState) -> Self {
        match old {
            OldProtocolContractState::NotInitialized => crate::state::ProtocolContractState::NotInitialized,
            OldProtocolContractState::Initializing(state) => {
                crate::state::ProtocolContractState::Initializing(state.into())
            }
            OldProtocolContractState::Running(state) => {
                crate::state::ProtocolContractState::Running(state.into())
            }
            OldProtocolContractState::Resharing(state) => {
                crate::state::ProtocolContractState::Resharing(state.into())
            }
        }
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: u64,
    /// The grace period duration for expiry of old mpc image hashes once a new one is added.
    pub tee_upgrade_deadline_duration_seconds: u64,
}

impl From<Config> for crate::config::Config {
    fn from(value: Config) -> Self {
        crate::config::Config {
            key_event_timeout_blocks: value.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: value.tee_upgrade_deadline_duration_seconds,
            ..Default::default()
        }
    }
}

/// Old version of [`UpdateEntry`] that included votes.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct UpdateEntry {
    update: Update,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

/// Old version of [`ProposedUpdates`] that used the old [`UpdateEntry`] with votes.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct ProposedUpdates {
    vote_by_participant: IterableMap<AccountId, UpdateId>,
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

impl From<ProposedUpdates> for crate::update::ProposedUpdates {
    fn from(old: ProposedUpdates) -> Self {
        // do_update() clears both entries and vote_by_participant after applying an update. If
        // we're migrating and find non-empty state, this indicates a bug or unexpected state
        // that should be investigated.
        if !old.entries.is_empty() {
            panic!(
                "Migration error: Found {} pending update entries. Expected empty state as do_update() clears entries.",
                old.entries.len()
            );
        }

        if !old.vote_by_participant.is_empty() {
            panic!(
                "Migration error: Found {} pending votes. Expected empty state as do_update() clears votes.",
                old.vote_by_participant.len()
            );
        }

        Self {
            vote_by_participant: IterableMap::new(
                crate::storage_keys::StorageKey::ProposedUpdatesVotesV2,
            ),
            entries: IterableMap::new(crate::storage_keys::StorageKey::ProposedUpdatesEntriesV2),
            id: old.id,
        }
    }
}

#[derive(Debug, BorshDeserialize)]
struct TeeState {
    _allowed_docker_image_hashes: AllowedDockerImageHashes,
    _allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    _votes: CodeHashesVotes,
    participants_attestations: IterableMap<near_sdk::PublicKey, (NodeId, Attestation)>,
}

#[derive(Debug, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        // Convert old protocol state to new protocol state (adds default foreign_chain_policy)
        let protocol_state: crate::state::ProtocolContractState = value.protocol_state.into();

        let crate::ProtocolContractState::Running(running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        // For the soft release we give every participant a mocked attestation.
        // Since this upgrade has a non-backwards compatible change, instead of manually mapping the attestations
        // we give everyone a new mock attestation again instead.
        // clear previous attestations from the storage trie
        let stale_participant_attestations = value.tee_state.participants_attestations;

        let threshold_parameters = &running_state.parameters.participants();
        let tee_state = crate::TeeState::with_mocked_participant_attestations(threshold_parameters);

        Self {
            protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: near_sdk::store::LookupMap::new(
                crate::storage_keys::StorageKey::PendingVerifyForeignTxRequests,
            ),
            proposed_updates: value.proposed_updates.into(),
            config: value.config.into(),
            tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {
                participant_attestations: Some(stale_participant_attestations),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{primitives::test_utils::gen_account_id, storage_keys::StorageKey};

    fn create_old_proposed_updates(id: u64) -> ProposedUpdates {
        ProposedUpdates {
            vote_by_participant: IterableMap::new(StorageKey::ProposedUpdatesVotesV2),
            entries: IterableMap::new(StorageKey::ProposedUpdatesEntriesV2),
            id: UpdateId(id),
        }
    }

    #[test]
    fn test_proposed_updates_migration_with_empty_state() {
        // given: Empty state (as expected in production after do_update() clears)
        let old = create_old_proposed_updates(42);

        // when
        let new: crate::update::ProposedUpdates = old.into();

        // then: New state preserves only the ID
        assert_eq!(new.entries.len(), 0);
        assert_eq!(new.vote_by_participant.len(), 0);
        assert_eq!(new.id, UpdateId(42));
    }

    #[test]
    #[should_panic(expected = "Migration error: Found 2 pending update entries")]
    fn test_proposed_updates_migration_panics_on_non_empty_entries() {
        // given: Unexpected non-empty entries
        let mut old = create_old_proposed_updates(0);
        old.entries.insert(
            UpdateId(1),
            UpdateEntry {
                update: Update::Contract(vec![1, 2, 3]),
                votes: HashSet::new(),
                bytes_used: 100,
            },
        );
        old.entries.insert(
            UpdateId(2),
            UpdateEntry {
                update: Update::Contract(vec![4, 5, 6]),
                votes: HashSet::new(),
                bytes_used: 200,
            },
        );

        // when: Try to migrate (should panic)
        let _new: crate::update::ProposedUpdates = old.into();
    }

    #[test]
    #[should_panic(expected = "Migration error: Found 1 pending vote")]
    fn test_proposed_updates_migration_panics_on_non_empty_votes() {
        // given: Unexpected non-empty votes
        let mut old = create_old_proposed_updates(0);
        let alice = gen_account_id();
        old.vote_by_participant.insert(alice, UpdateId(1));

        // when: Try to migrate (should panic)
        let _new: crate::update::ProposedUpdates = old.into();
    }
}
