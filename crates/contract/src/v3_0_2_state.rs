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
use std::collections::{BTreeMap, HashSet};

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
        let ProposedUpdates {
            mut entries,
            vote_by_participant,
            id,
        } = old;

        // Build map of update_id -> voters for validation
        let mut votes_by_update: BTreeMap<UpdateId, HashSet<AccountId>> = BTreeMap::new();
        for (account, update_id) in vote_by_participant.iter() {
            votes_by_update
                .entry(*update_id)
                .or_default()
                .insert(account.clone());
        }

        let entries_to_migrate: Vec<(UpdateId, crate::update::UpdateEntry)> = entries
            .iter()
            .map(|(id, entry)| {
                // Validate votes consistency
                if !votes_by_update
                    .get(id)
                    .map_or(entry.votes.is_empty(), |v| v == &entry.votes)
                {
                    near_sdk::env::log_str(&format!(
                        "Migration warning: Inconsistent votes for update {id:?}. Entry votes: {:?}, vote_by_participant: {:?}",
                        entry.votes,
                        votes_by_update.get(id)
                    ));
                }

                (
                    *id,
                    crate::update::UpdateEntry {
                        update: entry.update.clone(),
                        bytes_used: entry.bytes_used,
                    },
                )
            })
            .collect();

        // Load keys from storage and explicitly delete all old entries from V2
        let old_keys: Vec<UpdateId> = entries.keys().cloned().collect();
        for key in old_keys {
            entries.remove(&key);
        }

        let mut new_entries =
            IterableMap::new(crate::storage_keys::StorageKey::ProposedUpdatesEntriesV3);
        for (id, entry) in entries_to_migrate {
            new_entries.insert(id, entry);
        }

        Self {
            vote_by_participant,
            entries: new_entries,
            id,
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
    fn test_proposed_updates_migration_preserves_votes() {
        // given
        let mut old = create_old_proposed_updates(0);
        let accounts: Vec<AccountId> = (0..3).map(|_| gen_account_id()).collect();

        // Two updates: accounts[0]+accounts[1] vote for update 1, accounts[2] votes for update 2
        for (update_id, voters, code) in [
            (1, &accounts[0..2], vec![1, 2, 3]),
            (2, &accounts[2..3], vec![4, 5, 6]),
        ] {
            let id = UpdateId(update_id);
            let votes: HashSet<_> = voters.iter().cloned().collect();

            for voter in voters {
                old.vote_by_participant.insert(voter.clone(), id);
            }
            old.entries.insert(
                id,
                UpdateEntry {
                    update: Update::Contract(code),
                    votes,
                    bytes_used: update_id as u128 * 100,
                },
            );
        }

        // when
        let new: crate::update::ProposedUpdates = old.into();

        // then
        // Verification #1: All votes are preserved exactly as they were.
        // vote_by_participant map is reused directly, ensuring no vote data is lost.
        assert_eq!(
            new.vote_by_participant.get(&accounts[0]),
            Some(&UpdateId(1))
        );
        assert_eq!(
            new.vote_by_participant.get(&accounts[1]),
            Some(&UpdateId(1))
        );
        assert_eq!(
            new.vote_by_participant.get(&accounts[2]),
            Some(&UpdateId(2))
        );

        // Verification #2: Entries migrated to new storage WITHOUT redundant votes field.
        // Old UpdateEntry.votes field is NOT carried over, eliminating duplicate data.
        assert_eq!(new.entries.get(&UpdateId(1)).unwrap().bytes_used, 100);
        assert_eq!(new.entries.get(&UpdateId(2)).unwrap().bytes_used, 200);
        assert_eq!(new.id, UpdateId(0));
    }

    #[test]
    fn test_proposed_updates_migration_with_inconsistent_votes() {
        // given
        let mut old = create_old_proposed_updates(0);
        let alice = gen_account_id();
        let bob = gen_account_id();
        let id = UpdateId(1);

        // Inconsistent: alice in vote_by_participant, bob in entry.votes
        old.vote_by_participant.insert(alice.clone(), id);
        old.entries.insert(
            id,
            UpdateEntry {
                update: Update::Contract(vec![1, 2, 3]),
                votes: [bob.clone()].into(),
                bytes_used: 100,
            },
        );

        // when
        let new: crate::update::ProposedUpdates = old.into();

        // then
        // Verification: vote_by_participant is source of truth (alice's vote preserved).
        assert_eq!(new.vote_by_participant.get(&alice), Some(&id));
        assert_eq!(new.vote_by_participant.get(&bob), None);
        assert!(new.entries.get(&id).is_some());
    }

    #[test]
    fn test_proposed_updates_migration_multiple_updates() {
        // given
        let mut old = create_old_proposed_updates(5);

        // Create 3 updates with 1, 2, and 3 voters respectively
        let mut all_voters = Vec::new();
        for (update_num, voter_count) in [(1, 1), (2, 2), (3, 3)] {
            let id = UpdateId(update_num);
            let voters: Vec<AccountId> = (0..voter_count).map(|_| gen_account_id()).collect();

            for voter in &voters {
                old.vote_by_participant.insert(voter.clone(), id);
            }
            old.entries.insert(
                id,
                UpdateEntry {
                    update: Update::Contract(vec![update_num as u8]),
                    votes: voters.iter().cloned().collect(),
                    bytes_used: update_num as u128 * 100,
                },
            );
            all_voters.extend(voters);
        }

        // when
        let new: crate::update::ProposedUpdates = old.into();

        // then
        assert_eq!(new.entries.len(), 3);

        // Verification: All vote counts preserved correctly across multiple updates.
        // Each update retains its exact voter set through vote_by_participant.
        let vote_counts: [usize; 3] = [1, 2, 3].map(|expected_id| {
            new.vote_by_participant
                .iter()
                .filter(|(_, id)| id.0 == expected_id)
                .count()
        });
        assert_eq!(vote_counts, [1, 2, 3]);
    }

    #[test]
    fn test_migration_removes_v2_entries_from_storage() {
        // given: Create old ProposedUpdates with entries in V2 storage
        let mut old = create_old_proposed_updates(0);
        let id1 = UpdateId(1);
        let id2 = UpdateId(2);

        old.entries.insert(
            id1,
            UpdateEntry {
                update: Update::Contract(vec![1, 2, 3]),
                votes: HashSet::new(),
                bytes_used: 100,
            },
        );
        old.entries.insert(
            id2,
            UpdateEntry {
                update: Update::Contract(vec![4, 5, 6]),
                votes: HashSet::new(),
                bytes_used: 200,
            },
        );

        // Verify V2 storage has entries before migration
        assert_eq!(old.entries.len(), 2);

        // when: Perform migration (which should remove V2 entries)
        let _new: crate::update::ProposedUpdates = old.into();

        // then: Create a new IterableMap with V2 storage key and verify it's empty
        let v2_entries_after_migration: IterableMap<UpdateId, UpdateEntry> =
            IterableMap::new(StorageKey::ProposedUpdatesEntriesV2);

        // This proves .remove() deleted from storage, not just memory
        assert_eq!(
            v2_entries_after_migration.len(),
            0,
            "V2 storage should be empty after migration"
        );
        assert!(v2_entries_after_migration.get(&id1).is_none());
        assert!(v2_entries_after_migration.get(&id2).is_none());
    }
}
