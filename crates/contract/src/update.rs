use std::collections::HashSet;
use std::hash::Hash;

use crate::config::Config;
use crate::storage_keys::StorageKey;

use crate::errors::{ConversionError, Error};
use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise};

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema),
    derive(::borsh::BorshSchema)
)]
#[derive(
    Copy,
    Clone,
    Default,
    Debug,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct UpdateId(pub(crate) u64);

impl UpdateId {
    pub fn generate(&mut self) -> Self {
        let id = self.0;
        self.0 += 1;
        Self(id)
    }
}

impl From<u64> for UpdateId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Clone)]
pub enum Update {
    Contract(Vec<u8>),
    Config(Config),
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Default)]
pub struct ProposeUpdateArgs {
    pub code: Option<Vec<u8>>,
    pub config: Option<Config>,
}

impl TryFrom<ProposeUpdateArgs> for Update {
    type Error = Error;

    fn try_from(value: ProposeUpdateArgs) -> Result<Self, Self::Error> {
        let ProposeUpdateArgs { code, config } = value;
        let update = match (code, config) {
            (Some(contract), None) => Update::Contract(contract),
            (None, Some(config)) => Update::Config(config),
            (Some(_), Some(_)) => {
                return Err(ConversionError::DataConversion
                    .message("Code and config updates are not allowed at the same time"))
            }
            _ => {
                return Err(ConversionError::DataConversion
                    .message("Expected either code or config update, received none of them"))
            }
        };
        Ok(update)
    }
}

#[near(serializers=[borsh ])]
#[derive(Debug, PartialEq)]
struct UpdateEntry {
    update: Update,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

#[near(serializers=[borsh ])]
#[derive(Debug)]
pub struct ProposedUpdates {
    vote_by_participant: IterableMap<AccountId, UpdateId>,
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

impl Default for ProposedUpdates {
    fn default() -> Self {
        Self {
            vote_by_participant: IterableMap::new(StorageKey::ProposedUpdatesVotesV2),
            entries: IterableMap::new(StorageKey::ProposedUpdatesEntriesV2),
            id: UpdateId::default(),
        }
    }
}

impl ProposedUpdates {
    pub fn required_deposit(update: &Update) -> NearToken {
        required_deposit(bytes_used(update))
    }

    /// Propose an update given the new contract code and/or config.
    ///
    /// Returns UpdateId
    pub fn propose(&mut self, update: Update) -> UpdateId {
        let bytes_used = bytes_used(&update);

        let id = self.id.generate();
        self.entries.insert(
            id,
            UpdateEntry {
                update,
                votes: HashSet::new(),
                bytes_used,
            },
        );

        id
    }

    pub fn get_all(&self) -> Vec<(UpdateId, &Update, &HashSet<AccountId>)> {
        self.entries
            .iter()
            .map(|(update_id, entry)| (*update_id, &entry.update, &entry.votes))
            .collect()
    }

    pub fn remove_vote(&mut self, voter: &AccountId) {
        if let Some(previous_id) = self.vote_by_participant.remove(voter) {
            if let Some(entry) = self.entries.get_mut(&previous_id) {
                entry.votes.remove(voter);
            } else {
                env::log_str("inconsistent voting set");
            }
        }
    }

    /// Vote for the update with the given id.
    ///
    /// Returns Some(votes) if the given [`UpdateId`] exists, otherwise None.
    pub fn vote(&mut self, id: &UpdateId, voter: AccountId) -> Option<&HashSet<AccountId>> {
        // If participant has voted before, remove their vote
        self.remove_vote(&voter);
        // ensure that the update the participant is voting for exists
        let Some(update_entry) = self.entries.get_mut(id) else {
            env::log_str(&format!("no update with id {:?} exists", id));
            return None;
        };
        // record the vote
        self.vote_by_participant.insert(voter.clone(), *id);
        update_entry.votes.insert(voter);
        Some(&update_entry.votes)
    }

    pub fn do_update(&mut self, id: &UpdateId, gas: Gas) -> Option<Promise> {
        let entry = self.entries.remove(id)?;

        // Clear all entries as they might be no longer valid
        self.entries.clear();
        self.vote_by_participant.clear();

        let mut promise = Promise::new(env::current_account_id());
        match entry.update {
            Update::Contract(code) => {
                // deploy contract then do a `migrate` call to migrate state.
                promise = promise.deploy_contract(code).function_call(
                    "migrate".into(),
                    Vec::new(),
                    NearToken::from_near(0),
                    gas,
                );
            }
            Update::Config(config) => {
                promise = promise.function_call(
                    "update_config".into(),
                    serde_json::to_vec(&(&config,)).unwrap(),
                    NearToken::from_near(0),
                    gas,
                );
            }
        }
        Some(promise)
    }
}

fn bytes_used(update: &Update) -> u128 {
    let mut bytes_used = std::mem::size_of::<UpdateEntry>() as u128;

    // Assume a high max of 128 participant votes per update entry.
    bytes_used += 128 * std::mem::size_of::<AccountId>() as u128;

    match update {
        Update::Contract(code) => {
            bytes_used += code.len() as u128;
        }
        Update::Config(config) => {
            let bytes = serde_json::to_vec(&config).unwrap();
            bytes_used += bytes.len() as u128;
        }
    }

    bytes_used
}

fn required_deposit(bytes_used: u128) -> NearToken {
    env::storage_byte_cost().saturating_mul(bytes_used)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        primitives::test_utils::gen_account_id,
        update::{bytes_used, UpdateEntry, UpdateId},
    };

    use super::{ProposedUpdates, Update};

    #[test]
    fn test_proposed_updates_starts_empty() {
        let proposed_updates = ProposedUpdates::default();
        assert!(proposed_updates.vote_by_participant.is_empty());
        assert!(proposed_updates.entries.is_empty());
        assert_eq!(proposed_updates.id, 0.into());
        assert_eq!(proposed_updates.get_all(), Vec::new());
    }

    #[test]
    fn test_proposed_updates_propose_update() {
        let mut proposed_updates = ProposedUpdates::default();
        let update = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update);
        let extected_update_id = 0.into();
        // assert update id matches
        assert_eq!(proposed_updates.propose(update.clone()), extected_update_id);
        // assert proposal comes without votes
        assert!(proposed_updates.vote_by_participant.is_empty());
        let extected_update_entry = UpdateEntry {
            update: update.clone(),
            votes: HashSet::new(),
            bytes_used,
        };
        assert_eq!(
            proposed_updates.entries.get(&extected_update_id).unwrap(),
            &extected_update_entry
        );
        // assert update_id has been incremented
        assert_eq!(proposed_updates.id, 1.into());

        // assert get_all() fetches the correct result
        assert_eq!(
            proposed_updates.get_all(),
            vec![(extected_update_id, &update, &HashSet::new())]
        );
    }

    #[test]
    fn test_proposed_updates_vote_update_empty() {
        let mut proposed_updates = ProposedUpdates::default();
        let account_id = gen_account_id();
        assert!(proposed_updates
            .vote(&UpdateId(0), account_id.clone())
            .is_none());
        assert!(proposed_updates.vote_by_participant.is_empty());
        assert!(proposed_updates.entries.is_empty());
        assert_eq!(proposed_updates.id, 0.into());
        assert_eq!(proposed_updates.get_all(), vec![]);
    }

    #[test]
    fn test_proposed_updates_vote_update_simple() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        let update_1 = Update::Contract([1; 1000].into());
        let update_id_1 = proposed_updates.propose(update_1.clone());
        assert_eq!(proposed_updates.id, 2.into());
        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );
        assert_eq!(
            proposed_updates
                .vote_by_participant
                .get(&account_id)
                .unwrap(),
            &update_id_0
        );
        assert_eq!(
            proposed_updates.get_all(),
            vec![
                (update_id_0, &update_0, &HashSet::from([account_id.clone()])),
                (update_id_1, &update_1, &HashSet::from([]))
            ]
        );
    }

    #[test]
    fn test_proposed_updates_change_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        let update_1 = Update::Contract([1; 1000].into());
        let update_id_1 = proposed_updates.propose(update_1.clone());
        assert_eq!(proposed_updates.id, 2.into());
        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );
        // change vote
        assert_eq!(
            proposed_updates
                .vote(&update_id_1, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );
        assert_eq!(
            proposed_updates
                .vote_by_participant
                .get(&account_id)
                .unwrap(),
            &update_id_1
        );
        assert_eq!(
            proposed_updates.get_all(),
            vec![
                (update_id_0, &update_0, &HashSet::from([])),
                (update_id_1, &update_1, &HashSet::from([account_id.clone()]))
            ]
        );
    }

    #[test]
    fn test_proposed_updates_remove_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(proposed_updates.id, 1.into());
        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );
        assert_eq!(
            proposed_updates
                .vote_by_participant
                .get(&account_id)
                .unwrap(),
            &update_id_0
        );
        assert_eq!(
            proposed_updates.get_all(),
            vec![(update_id_0, &update_0, &HashSet::from([account_id.clone()])),]
        );
        proposed_updates.remove_vote(&account_id);
        assert_eq!(
            proposed_updates.get_all(),
            vec![(update_id_0, &update_0, &HashSet::from([])),]
        );
        assert_eq!(proposed_updates.vote_by_participant.get(&account_id), None);
    }

    #[test]
    fn test_proposed_updates_invalid_vote_removes_previous_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(proposed_updates.id, 1.into());
        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );
        assert_eq!(
            proposed_updates
                .vote_by_participant
                .get(&account_id)
                .unwrap(),
            &update_id_0
        );
        assert_eq!(
            proposed_updates.get_all(),
            vec![(update_id_0, &update_0, &HashSet::from([account_id.clone()])),]
        );
        assert!(proposed_updates
            .vote(&100.into(), account_id.clone())
            .is_none());
        assert_eq!(
            proposed_updates.get_all(),
            vec![(update_id_0, &update_0, &HashSet::from([])),]
        );
        assert_eq!(proposed_updates.vote_by_participant.get(&account_id), None);
    }
}
