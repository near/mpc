use std::collections::HashSet;
use std::hash::Hash;

use crate::primitives::participants::Participants;
use crate::storage_keys::StorageKey;

use crate::errors::{ConversionError, Error};
use borsh::{self, BorshDeserialize, BorshSerialize};
use derive_more::Deref;
use near_account_id::AccountId;
use near_sdk::{
    env, near,
    serde::{Deserialize, Serialize},
    store::IterableMap,
    Gas, NearToken, Promise,
};

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
    Deref,
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum Update {
    Contract(Vec<u8>),
    Config(contract_interface::types::Config),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProposeUpdateArgs {
    pub code: Option<Vec<u8>>,
    pub config: Option<contract_interface::types::Config>,
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
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
    /// Returns `Some(votes)` if the given [`UpdateId`] exists, otherwise `None`.
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
                    "migrate",
                    Vec::new(),
                    NearToken::from_near(0),
                    gas,
                );
            }
            Update::Config(config) => {
                promise = promise.function_call(
                    "update_config",
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

    /// Removes votes from the specified accounts.
    pub fn remove_votes(&mut self, accounts_to_remove: &[AccountId]) {
        accounts_to_remove
            .iter()
            .for_each(|account| self.remove_vote(account));
    }

    /// Removes votes from accounts that are not participants.
    pub fn remove_non_participant_votes(&mut self, participants: &Participants) {
        // Note: This operation has quadratic time complexity.
        // TODO issue [#1572](https://github.com/near/mpc/issues/1572)
        let non_participants: Vec<AccountId> = self
            .vote_by_participant
            .keys()
            .filter(|voter| !participants.is_participant(voter))
            .cloned()
            .collect();

        self.remove_votes(&non_participants);
    }

    /// Returns all account IDs that have voted.
    #[cfg(test)]
    pub fn voters(&self) -> Vec<AccountId> {
        self.vote_by_participant.keys().cloned().collect()
    }

    pub fn all_updates(&self) -> Vec<(UpdateId, &Update, &HashSet<AccountId>)> {
        self.entries
            .iter()
            .map(|(update_id, entry)| (*update_id, &entry.update, &entry.votes))
            .collect()
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
    use near_account_id::AccountId;
    use near_sdk::Gas;
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use test_utils::contract_types::dummy_config;

    /// Helper struct for testing. Similar to [`ProposedUpdates`] but with native types and no
    /// ephemeral vote count by participant id.
    #[derive(Debug, PartialEq)]
    struct TestUpdateVotes {
        /// the next update id
        id: u64,
        /// map from update id to UpdateEntry
        entries: BTreeMap<u64, UpdateEntry>,
    }

    /// Ensure that the default [`ProposedUpdates`] struct is empty.
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

    /// Asserts that voting for a non-existing [`UpdateId`] does not record a vote.
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

    /// Asserts that voting for a valid [`UpdateId`] is recorded.
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

    /// Asserts that [`ProposedUpdates::remove_vote`] removes the vote associated with the given [`AccountId`].
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

    /// Asserts that [`ProposedUpdates::do_update`] clears all entries and votes.
    #[test]
    fn test_proposed_updates_do_update_clears_all_state() {
        // Given: multiple update proposals with votes from different accounts
        let mut proposed_updates = ProposedUpdates::default();

        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());

        let update_1 = Update::Contract([1; 1000].into());
        let update_id_1 = proposed_updates.propose(update_1.clone());

        let update_2 = Update::Config(dummy_config(1));
        let update_id_2 = proposed_updates.propose(update_2.clone());

        let account_0 = gen_account_id();
        let account_1 = gen_account_id();
        let account_2 = gen_account_id();

        proposed_updates.vote(&update_id_0, account_0.clone());
        proposed_updates.vote(&update_id_1, account_1.clone());
        proposed_updates.vote(&update_id_2, account_2.clone());

        let before: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        let expected_before = TestUpdateVotes {
            id: 3,
            entries: BTreeMap::from([
                (
                    0,
                    UpdateEntry {
                        update: update_0.clone(),
                        votes: HashSet::from([account_0.clone()]),
                        bytes_used: bytes_used(&update_0),
                    },
                ),
                (
                    1,
                    UpdateEntry {
                        update: update_1.clone(),
                        votes: HashSet::from([account_1.clone()]),
                        bytes_used: bytes_used(&update_1),
                    },
                ),
                (
                    2,
                    UpdateEntry {
                        update: update_2.clone(),
                        votes: HashSet::from([account_2.clone()]),
                        bytes_used: bytes_used(&update_2),
                    },
                ),
            ]),
        };
        assert_eq!(before, expected_before);

        // When: executing an update
        proposed_updates.do_update(&update_id_1, Gas::from_tgas(100));

        // Then: all state is cleared (entries and votes)
        let after: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        let expected_after = TestUpdateVotes {
            id: 3,
            entries: BTreeMap::new(),
        };
        assert_eq!(after, expected_after);
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

    #[test]
    fn test_proposed_updates_all_updates() {
        let mut proposed_updates = ProposedUpdates::default();
        assert_eq!(proposed_updates.all_updates(), vec![]);
        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let update_1 = Update::Contract([1; 1000].into());
        let update_id_1 = proposed_updates.propose(update_1.clone());
        assert_eq!(update_id_1.0, 1);

        let update_2 = Update::Config(dummy_config(2));
        let update_id_2 = proposed_updates.propose(update_2.clone());
        assert_eq!(update_id_2.0, 2);

        let votes_0 = {
            let account_id = gen_account_id();
            let expected_votes = HashSet::from([account_id.clone()]);
            let votes_0 = proposed_updates
                .vote(&update_id_0, account_id.clone())
                .unwrap();
            assert_eq!(&expected_votes, votes_0);
            expected_votes
        };

        let votes_1 = {
            let account_id = gen_account_id();
            let expected_votes = HashSet::from([account_id.clone()]);
            let votes_1 = proposed_updates
                .vote(&update_id_1, account_id.clone())
                .unwrap();
            assert_eq!(&expected_votes, votes_1);
            expected_votes
        };

        let votes_2 = {
            let account_id = gen_account_id();
            let expected_votes = HashSet::from([account_id.clone()]);
            let votes_2 = proposed_updates
                .vote(&update_id_2, account_id.clone())
                .unwrap();
            assert_eq!(&expected_votes, votes_2);
            expected_votes
        };

        let expected = vec![
            (update_id_0, &update_0, &votes_0),
            (update_id_1, &update_1, &votes_1),
            (update_id_2, &update_2, &votes_2),
        ];

        let mut res = proposed_updates.all_updates();
        res.sort_by_key(|(update_id, _, _)| *update_id);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_proposed_updates_remove_votes() {
        let mut proposed_updates = ProposedUpdates::default();
        let update = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update);
        let update_id = proposed_updates.propose(update.clone());

        let (acc0, acc1, acc2) = (gen_account_id(), gen_account_id(), gen_account_id());
        proposed_updates.vote(&update_id, acc0.clone());
        proposed_updates.vote(&update_id, acc1.clone());
        proposed_updates.vote(&update_id, acc2.clone());

        proposed_updates.remove_votes(&[acc0, acc2]);

        let expected = TestUpdateVotes {
            id: 1,
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    votes: HashSet::from([acc1]),
                    bytes_used,
                },
            )]),
        };

        let result: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_proposed_updates_remove_non_participant_votes() {
        use crate::primitives::test_utils::gen_participants;

        let mut proposed_updates = ProposedUpdates::default();
        let update = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update);
        let update_id = proposed_updates.propose(update.clone());

        let participants = gen_participants(2);
        let (acc0, acc1) = (
            &participants.participants()[0].0,
            &participants.participants()[1].0,
        );
        let (acc2, acc3) = (gen_account_id(), gen_account_id());

        proposed_updates.vote(&update_id, acc0.clone());
        proposed_updates.vote(&update_id, acc1.clone());
        proposed_updates.vote(&update_id, acc2);
        proposed_updates.vote(&update_id, acc3);

        proposed_updates.remove_non_participant_votes(&participants);

        let expected = TestUpdateVotes {
            id: 1,
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    votes: HashSet::from([acc0.clone(), acc1.clone()]),
                    bytes_used,
                },
            )]),
        };

        let result: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_proposed_updates_voters() {
        let mut proposed_updates = ProposedUpdates::default();
        assert!(proposed_updates.voters().is_empty());

        let update = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update);
        let update_id = proposed_updates.propose(update.clone());
        let (acc0, acc1, acc2) = (gen_account_id(), gen_account_id(), gen_account_id());

        proposed_updates.vote(&update_id, acc0.clone());
        proposed_updates.vote(&update_id, acc1.clone());
        proposed_updates.vote(&update_id, acc2.clone());

        let voters: HashSet<_> = proposed_updates.voters().into_iter().collect();
        assert_eq!(
            voters,
            HashSet::from([acc0.clone(), acc1.clone(), acc2.clone()])
        );

        let expected_after_votes = TestUpdateVotes {
            id: 1,
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    votes: HashSet::from([acc0.clone(), acc1.clone(), acc2.clone()]),
                    bytes_used,
                },
            )]),
        };
        let result: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(result, expected_after_votes);

        proposed_updates.remove_vote(&acc1);
        let voters: HashSet<_> = proposed_updates.voters().into_iter().collect();
        assert_eq!(voters, HashSet::from([acc0.clone(), acc2.clone()]));

        let expected_after_removal = TestUpdateVotes {
            id: 1,
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    votes: HashSet::from([acc0, acc2]),
                    bytes_used,
                },
            )]),
        };
        let result: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(result, expected_after_removal);
    }
}
