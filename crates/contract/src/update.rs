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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, PartialEq, Clone)]
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

    /// Removes any existing vote by `voter`.
    /// Sets `voter`s vote for the update with the given id.
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

    // todo [#1486](https://github.com/near/mpc/issues/1486): below function should have a unit test, as we rely on its cleanup mechanism during migration
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

    /// Removes the vote for [`AccountId`]
    pub fn remove_vote(&mut self, voter: &AccountId) {
        if let Some(previous_id) = self.vote_by_participant.remove(voter) {
            if let Some(entry) = self.entries.get_mut(&previous_id) {
                entry.votes.remove(voter);
            } else {
                env::log_str("inconsistent voting set");
            }
        }
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
    use crate::{
        primitives::test_utils::gen_account_id,
        update::{bytes_used, ProposedUpdates, Update, UpdateEntry, UpdateId},
    };
    use near_sdk::AccountId;
    use std::collections::{BTreeMap, BTreeSet, HashSet};

    /// Helper struct for testing. Similar to [`ProposedUpdates`] but with native types and no
    /// ephemeral vote count by participant id.
    #[derive(Debug, PartialEq)]
    struct TestUpdateVotes {
        /// the next update id
        id: u64,
        /// map from update id to UpdateEntry
        entries: BTreeMap<u64, UpdateEntry>,
    }

    /// Ensure that the default struct is empty
    #[test]
    fn test_proposed_updates_starts_empty() {
        let proposed_updates = ProposedUpdates::default();
        let expected = TestUpdateVotes {
            id: 0,
            entries: BTreeMap::new(),
        };
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// Ensures that [`ProposedUpdates::propose`]:
    /// - returns the [`UpdateId`] of the proposed update
    /// - inserst the [`UpdateEntry`] into the entries map
    /// - does **not** record a vote for the newly proposed update
    #[test]
    fn test_proposed_updates_propose_update() {
        let mut proposed_updates = ProposedUpdates::default();
        let update = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update);
        let expected_update_id = 0.into();
        // assert return value (update id) matches
        assert_eq!(proposed_updates.propose(update.clone()), expected_update_id);

        let expected = TestUpdateVotes {
            id: 1, // next update id must have been incremented
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    votes: HashSet::new(), // ensure proposal does not come with a vote
                    bytes_used,
                },
            )]),
        };
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// asserts that voting for a non-existing update id does not record a vote
    #[test]
    fn test_proposed_updates_vote_update_empty() {
        let mut proposed_updates = ProposedUpdates::default();
        let account_id = gen_account_id();
        assert!(proposed_updates
            .vote(&UpdateId(0), account_id.clone())
            .is_none());

        let expected = TestUpdateVotes {
            id: 0,
            entries: BTreeMap::new(),
        };
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// asserts that voting for a valid update id is recorded
    #[test]
    fn test_proposed_updates_vote_update_simple() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let update_1 = Update::Contract([1; 1000].into());
        let bytes_used = bytes_used(&update_0);
        let update_id_1 = proposed_updates.propose(update_1.clone());
        assert_eq!(update_id_1.0, 1);

        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );

        let expected = TestUpdateVotes {
            id: 2,
            entries: BTreeMap::from([
                (
                    0,
                    UpdateEntry {
                        update: update_0.clone(),
                        votes: HashSet::from([account_id.clone()]),
                        bytes_used,
                    },
                ),
                (
                    1,
                    UpdateEntry {
                        update: update_1.clone(),
                        votes: HashSet::new(),
                        bytes_used,
                    },
                ),
            ]),
        };

        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// asserts that `remove_vote(account_id)` removes the vote associated to [`AccountId`]
    #[test]
    fn test_proposed_updates_remove_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update_0);
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );

        proposed_updates.remove_vote(&account_id);

        let expected = TestUpdateVotes {
            id: 1,
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update_0.clone(),
                    votes: HashSet::new(),
                    bytes_used,
                },
            )]),
        };

        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// asserts that a vote by [`AccountId`] can be changed
    #[test]
    fn test_proposed_updates_change_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let update_1 = Update::Contract([1; 1000].into());
        let bytes_used = bytes_used(&update_0);
        let update_id_1 = proposed_updates.propose(update_1.clone());
        assert_eq!(update_id_1.0, 1);

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

        let expected = TestUpdateVotes {
            id: 2,
            entries: BTreeMap::from([
                (
                    0,
                    UpdateEntry {
                        update: update_0.clone(),
                        votes: HashSet::new(),
                        bytes_used,
                    },
                ),
                (
                    1,
                    UpdateEntry {
                        update: update_1.clone(),
                        votes: HashSet::from([account_id.clone()]),
                        bytes_used,
                    },
                ),
            ]),
        };

        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// asserts that a vote for a non-existing update id by [`AccountId`] removes any previous vote by [`AccountId`]
    #[test]
    fn test_proposed_updates_invalid_vote_removes_previous_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update_0);
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let account_id = gen_account_id();
        assert_eq!(
            proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap(),
            &HashSet::from([account_id.clone()])
        );

        assert!(proposed_updates
            .vote(&100.into(), account_id.clone())
            .is_none());

        let expected = TestUpdateVotes {
            id: 1,
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update_0.clone(),
                    votes: HashSet::new(),
                    bytes_used,
                },
            )]),
        };

        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// Helper function
    impl TryFrom<&ProposedUpdates> for TestUpdateVotes {
        type Error = anyhow::Error;

        /// converts `ProposedUpdates` to `TestUpdateVotes`. Fails if `ProposedUpdates` has an
        /// inconsistent state.
        fn try_from(value: &ProposedUpdates) -> anyhow::Result<Self> {
            let id = value.id.0;

            // Convert entries: IterableMap<UpdateId, UpdateEntry> → BTreeMap<u64, UpdateEntry>
            let entries: BTreeMap<u64, UpdateEntry> = value
                .entries
                .iter()
                .map(|(id, entry)| (id.0, entry.clone()))
                .collect();

            // Record all votes
            let mut accounts_voted: BTreeSet<&AccountId> = BTreeSet::new();
            for entry in entries.values() {
                for account_id in &entry.votes {
                    if !accounts_voted.insert(account_id) {
                        anyhow::bail!("Invalid state: account {account_id:?} voted more than once.")
                    }
                }
            }

            // Ensure that [`ProposedUpdates`] is consistent
            let expected_accounts: BTreeSet<_> = value.vote_by_participant.keys().collect();
            anyhow::ensure!(
                accounts_voted == expected_accounts,
                "invalid state: vote_by_participant does not match votes in entries. votes by participant: {:?}, votes recorded: {:?}",
                expected_accounts,
                accounts_voted
            );

            Ok(TestUpdateVotes { id, entries })
        }
    }
}
