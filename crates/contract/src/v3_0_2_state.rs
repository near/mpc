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
        // Build map of update_id -> voters for validation
        let mut votes_by_update: BTreeMap<UpdateId, HashSet<AccountId>> = BTreeMap::new();
        for (account, update_id) in old.vote_by_participant.iter() {
            votes_by_update
                .entry(*update_id)
                .or_default()
                .insert(account.clone());
        }

        let entries_to_migrate: Vec<(UpdateId, crate::update::UpdateEntry)> = old
            .entries
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

        let mut entries =
            IterableMap::new(crate::storage_keys::StorageKey::ProposedUpdatesEntriesV2);
        for (id, entry) in entries_to_migrate {
            entries.insert(id, entry);
        }

        Self {
            vote_by_participant: old.vote_by_participant,
            entries,
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
