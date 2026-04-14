use std::collections::BTreeMap;
use std::hash::Hash;

use crate::{
    dto_mapping::IntoInterfaceType,
    errors::{Error, InvalidParameters},
    primitives::participants::Participants,
    storage_keys::StorageKey,
};
use borsh::{self, BorshDeserialize, BorshSerialize};
use derive_more::Deref;
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::UpdateHash;
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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum Update {
    Contract(Vec<u8>),
    Config(near_mpc_contract_interface::types::Config),
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
    pub config: near_mpc_contract_interface::types::Config,
}

impl From<ProposeUpdateArgs> for Update {
    fn from(value: ProposeUpdateArgs) -> Self {
        Update::Config(value.config)
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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub(crate) struct UpdateEntry {
    pub(super) update: Update,
    pub(super) bytes_used: u128,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct UpdateVotes {
    pub(super) votes: BTreeMap<AccountId, UpdateId>,
    pub(super) updates: BTreeMap<UpdateId, UpdateHash>,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct StagedContractUpload {
    pub chunks: Vec<Vec<u8>>,
    pub total_size: u64,
    pub received_bytes: u64,
    pub deposited: NearToken,
}

impl StagedContractUpload {
    pub fn new(total_size: u64) -> Self {
        Self {
            chunks: Vec::new(),
            total_size,
            received_bytes: 0,
            deposited: NearToken::from_yoctonear(0),
        }
    }

    pub fn append_chunk(&mut self, data: Vec<u8>) -> Result<(), Error> {
        let new_received = self.received_bytes + data.len() as u64;
        if new_received > self.total_size {
            return Err(InvalidParameters::MalformedPayload {
                reason: format!(
                    "Chunk would exceed declared total_size. received_bytes={}, chunk_len={}, total_size={}",
                    self.received_bytes, data.len(), self.total_size
                ),
            }
            .into());
        }
        self.received_bytes = new_received;
        self.chunks.push(data);
        Ok(())
    }

    pub fn assemble(self) -> Result<Vec<u8>, Error> {
        if self.received_bytes != self.total_size {
            return Err(InvalidParameters::MalformedPayload {
                reason: format!(
                    "Upload incomplete. received_bytes={}, total_size={}",
                    self.received_bytes, self.total_size
                ),
            }
            .into());
        }
        let mut assembled = Vec::with_capacity(self.total_size as usize);
        for chunk in self.chunks {
            assembled.extend_from_slice(&chunk);
        }
        Ok(assembled)
    }

    pub fn required_deposit_for_bytes(len: usize) -> NearToken {
        env::storage_byte_cost().saturating_mul(len as u128)
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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct StartContractUploadArgs {
    pub total_size: u64,
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
pub struct UploadContractChunkArgs {
    pub data: Vec<u8>,
}

#[near(serializers=[borsh ])]
#[derive(Debug)]
pub struct ProposedUpdates {
    pub(super) vote_by_participant: IterableMap<AccountId, UpdateId>,
    pub(super) entries: IterableMap<UpdateId, UpdateEntry>,
    pub(super) id: UpdateId,
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
    pub fn propose(&mut self, update: Update) -> UpdateId {
        let bytes_used = bytes_used(&update);

        let id = self.id.generate();
        self.entries.insert(id, UpdateEntry { update, bytes_used });

        id
    }

    /// Records a vote by [`AccountId`] for the update with the given [`UpdateId`].
    ///
    /// If the voter has already voted for a different update, that vote is automatically removed
    /// (each participant can only vote for one update at a time).
    ///
    /// Returns `None` if the [`UpdateId`] doesn't exist.
    pub fn vote(&mut self, id: &UpdateId, voter: AccountId) -> Option<()> {
        self.remove_vote(&voter);

        if !self.entries.contains_key(id) {
            env::log_str(&format!("no update with id {:?} exists", id));
            return None;
        };

        self.vote_by_participant.insert(voter.clone(), *id);

        Some(())
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
                    method_names::MIGRATE,
                    Vec::new(),
                    NearToken::from_near(0),
                    gas,
                );
            }
            Update::Config(config) => {
                // If we vote for a new config, we should use
                // the value `contract_upgrade_deposit_tera_gas` from the config
                // as the new gas value
                let new_config_gas_value = Gas::from_tgas(config.contract_upgrade_deposit_tera_gas);
                promise = promise.function_call(
                    method_names::UPDATE_CONFIG,
                    serde_json::to_vec(&(&config,)).unwrap(),
                    NearToken::from_near(0),
                    new_config_gas_value,
                );
            }
        }
        Some(promise)
    }

    /// Removes the vote for [`AccountId`].
    pub fn remove_vote(&mut self, voter: &AccountId) {
        self.vote_by_participant.remove(voter);
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
        // TODO(#1572): optimize quadratic time complexity
        let non_participants: Vec<AccountId> = self
            .vote_by_participant
            .keys()
            .filter(|voter| !participants.is_participant_given_account_id(voter))
            .cloned()
            .collect();

        self.remove_votes(&non_participants);
    }

    /// Returns all account IDs that have voted.
    #[cfg(test)]
    pub fn voters(&self) -> Vec<AccountId> {
        self.vote_by_participant.keys().cloned().collect()
    }

    pub(super) fn all_updates(&self) -> UpdateVotes {
        let votes = self
            .vote_by_participant
            .iter()
            .map(|(account, update_id)| (account.clone(), *update_id))
            .collect();

        let updates = self
            .entries
            .iter()
            .map(|(update_id, entry)| (*update_id, (&entry.update).into_dto_type()))
            .collect();

        UpdateVotes { votes, updates }
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
        dto_mapping::IntoInterfaceType,
        primitives::test_utils::{gen_account_id, gen_participants},
        update::{bytes_used, ProposedUpdates, Update, UpdateEntry, UpdateId},
    };
    use near_account_id::AccountId;
    use near_sdk::Gas;
    use std::collections::{BTreeMap, HashSet};
    use test_utils::contract_types::dummy_config;

    /// Helper struct for testing. Mirrors [`ProposedUpdates`] structure with native types.
    #[derive(Debug, PartialEq)]
    struct TestUpdateVotes {
        id: u64,
        votes: BTreeMap<AccountId, u64>,
        entries: BTreeMap<u64, UpdateEntry>,
    }

    /// Ensure that the default [`ProposedUpdates`] struct is empty.
    #[test]
    fn test_proposed_updates_starts_empty() {
        let proposed_updates = ProposedUpdates::default();
        let expected = TestUpdateVotes {
            id: 0,
            votes: BTreeMap::new(),
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
            id: 1,                  // next update id must have been incremented
            votes: BTreeMap::new(), // ensure proposal does not come with a vote
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
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
            votes: BTreeMap::new(),
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
        proposed_updates
            .vote(&update_id_0, account_id.clone())
            .unwrap();

        let expected = TestUpdateVotes {
            id: 2,
            votes: BTreeMap::from([(account_id.clone(), 0)]),
            entries: BTreeMap::from([
                (
                    0,
                    UpdateEntry {
                        update: update_0.clone(),
                        bytes_used,
                    },
                ),
                (
                    1,
                    UpdateEntry {
                        update: update_1.clone(),
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
        proposed_updates
            .vote(&update_id_0, account_id.clone())
            .unwrap();

        let mut expected = TestUpdateVotes {
            id: 1,
            votes: BTreeMap::from([(account_id.clone(), 0)]),
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update_0.clone(),
                    bytes_used,
                },
            )]),
        };
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);

        proposed_updates.remove_vote(&account_id);

        expected.votes = BTreeMap::new();
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// Asserts that a vote by [`AccountId`] can be changed.
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
        proposed_updates
            .vote(&update_id_0, account_id.clone())
            .unwrap();

        let mut expected = TestUpdateVotes {
            id: 2,
            votes: BTreeMap::from([(account_id.clone(), 0)]),
            entries: BTreeMap::from([
                (
                    0,
                    UpdateEntry {
                        update: update_0.clone(),
                        bytes_used,
                    },
                ),
                (
                    1,
                    UpdateEntry {
                        update: update_1.clone(),
                        bytes_used,
                    },
                ),
            ]),
        };

        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);

        // change vote
        proposed_updates
            .vote(&update_id_1, account_id.clone())
            .unwrap();

        expected.votes = BTreeMap::from([(account_id.clone(), 1)]);
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);
    }

    /// Asserts that a vote for a non-existing [`UpdateId`] by [`AccountId`] removes any previous vote by [`AccountId`].
    #[test]
    fn test_proposed_updates_invalid_vote_removes_previous_vote() {
        let mut proposed_updates = ProposedUpdates::default();
        let update_0 = Update::Contract([0; 1000].into());
        let bytes_used = bytes_used(&update_0);
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let account_id = gen_account_id();
        proposed_updates
            .vote(&update_id_0, account_id.clone())
            .unwrap();

        let mut expected = TestUpdateVotes {
            id: 1,
            votes: BTreeMap::from([(account_id.clone(), 0)]),
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update_0.clone(),
                    bytes_used,
                },
            )]),
        };
        let found: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(found, expected);

        assert!(proposed_updates
            .vote(&100.into(), account_id.clone())
            .is_none());

        expected.votes = BTreeMap::new();
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
            votes: BTreeMap::from([
                (account_0.clone(), 0),
                (account_1.clone(), 1),
                (account_2.clone(), 2),
            ]),
            entries: BTreeMap::from([
                (
                    0,
                    UpdateEntry {
                        update: update_0.clone(),
                        bytes_used: bytes_used(&update_0),
                    },
                ),
                (
                    1,
                    UpdateEntry {
                        update: update_1.clone(),
                        bytes_used: bytes_used(&update_1),
                    },
                ),
                (
                    2,
                    UpdateEntry {
                        update: update_2.clone(),
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
            votes: BTreeMap::new(),
            entries: BTreeMap::new(),
        };
        assert_eq!(after, expected_after);
    }

    impl TryFrom<&ProposedUpdates> for TestUpdateVotes {
        type Error = anyhow::Error;

        fn try_from(value: &ProposedUpdates) -> anyhow::Result<Self> {
            let id = value.id.0;

            let votes: BTreeMap<AccountId, u64> = value
                .vote_by_participant
                .iter()
                .map(|(account, update_id)| (account.clone(), update_id.0))
                .collect();

            let entries: BTreeMap<u64, UpdateEntry> = value
                .entries
                .iter()
                .map(|(update_id, entry)| (update_id.0, entry.clone()))
                .collect();

            Ok(TestUpdateVotes { id, votes, entries })
        }
    }

    #[test]
    fn test_proposed_updates_all_updates() {
        let mut proposed_updates = ProposedUpdates::default();
        let result = proposed_updates.all_updates();
        assert_eq!(result.votes, BTreeMap::new());
        assert_eq!(result.updates, BTreeMap::new());

        let update_0 = Update::Contract([0; 1000].into());
        let update_id_0 = proposed_updates.propose(update_0.clone());
        assert_eq!(update_id_0.0, 0);
        let update_1 = Update::Contract([1; 1000].into());
        let update_id_1 = proposed_updates.propose(update_1.clone());
        assert_eq!(update_id_1.0, 1);

        let update_2 = Update::Config(dummy_config(2));
        let update_id_2 = proposed_updates.propose(update_2.clone());
        assert_eq!(update_id_2.0, 2);

        let account_0 = gen_account_id();
        proposed_updates.vote(&update_id_0, account_0.clone());

        let account_1 = gen_account_id();
        proposed_updates.vote(&update_id_1, account_1.clone());

        let account_2 = gen_account_id();
        proposed_updates.vote(&update_id_2, account_2.clone());

        let result = proposed_updates.all_updates();

        let expected_votes = BTreeMap::from([
            (account_0, update_id_0),
            (account_1, update_id_1),
            (account_2, update_id_2),
        ]);
        assert_eq!(result.votes, expected_votes);

        let expected_updates = BTreeMap::from([
            (update_id_0, (&update_0).into_dto_type()),
            (update_id_1, (&update_1).into_dto_type()),
            (update_id_2, (&update_2).into_dto_type()),
        ]);
        assert_eq!(result.updates, expected_updates);
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
            votes: BTreeMap::from([(acc1.clone(), 0)]),
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    bytes_used,
                },
            )]),
        };

        let result: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_proposed_updates_remove_non_participant_votes() {
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
            votes: BTreeMap::from([(acc0.clone(), 0), (acc1.clone(), 0)]),
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
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
            votes: BTreeMap::from([(acc0.clone(), 0), (acc1.clone(), 0), (acc2.clone(), 0)]),
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
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
            votes: BTreeMap::from([(acc0.clone(), 0), (acc2.clone(), 0)]),
            entries: BTreeMap::from([(
                0,
                UpdateEntry {
                    update: update.clone(),
                    bytes_used,
                },
            )]),
        };
        let result: TestUpdateVotes = (&proposed_updates).try_into().unwrap();
        assert_eq!(result, expected_after_removal);
    }

    mod staged_upload {
        use super::super::StagedContractUpload;

        #[test]
        fn test_append_chunk_tracks_received_bytes() {
            let mut staged = StagedContractUpload::new(100);
            staged.append_chunk(vec![0u8; 40]).unwrap();
            assert_eq!(staged.received_bytes, 40);
            assert_eq!(staged.chunks.len(), 1);

            staged.append_chunk(vec![1u8; 60]).unwrap();
            assert_eq!(staged.received_bytes, 100);
            assert_eq!(staged.chunks.len(), 2);
        }

        #[test]
        fn test_append_chunk_rejects_exceeding_total_size() {
            let mut staged = StagedContractUpload::new(50);
            staged.append_chunk(vec![0u8; 40]).unwrap();
            let err = staged.append_chunk(vec![0u8; 20]).unwrap_err();
            assert!(err.to_string().contains("exceed declared total_size"));
        }

        #[test]
        fn test_assemble_concatenates_chunks() {
            let mut staged = StagedContractUpload::new(6);
            staged.append_chunk(vec![1, 2, 3]).unwrap();
            staged.append_chunk(vec![4, 5, 6]).unwrap();
            let assembled = staged.assemble().unwrap();
            assert_eq!(assembled, vec![1, 2, 3, 4, 5, 6]);
        }

        #[test]
        fn test_assemble_rejects_incomplete_upload() {
            let mut staged = StagedContractUpload::new(100);
            staged.append_chunk(vec![0u8; 50]).unwrap();
            let err = staged.assemble().unwrap_err();
            assert!(err.to_string().contains("incomplete"));
        }
    }
}
