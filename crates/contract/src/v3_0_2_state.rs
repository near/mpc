//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_account_id::AccountId;
use near_sdk::store::{IterableMap, LookupMap};
use std::collections::HashSet;

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::TeeState,
    update::{Update, UpdateId},
};

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

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
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
        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            proposed_updates: value.proposed_updates.into(),
            config: value.config.into(),
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
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
