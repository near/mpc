use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::config::Config;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, AccountId, Gas, NearToken, Promise};

#[derive(
    Copy,
    Clone,
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

impl From<u64> for UpdateId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Update {
    Config(Config),
    Contract(Vec<u8>),
}

#[derive(Default, Debug, BorshSerialize, BorshDeserialize)]
pub struct ProposedUpdates {
    updates: HashMap<UpdateId, Vec<Update>>,
    votes: HashMap<UpdateId, HashSet<AccountId>>,
    next_id: u64,
}

impl ProposedUpdates {
    /// Propose an update given the new contract code and/or config.
    ///
    /// Returns Some(UpdateId) if the update was successfully proposed, otherwise None.
    pub fn propose(&mut self, code: Option<Vec<u8>>, config: Option<Config>) -> Option<UpdateId> {
        let updates = match (code, config) {
            (Some(contract), Some(config)) => {
                vec![Update::Contract(contract), Update::Config(config)]
            }
            (Some(contract), None) => vec![Update::Contract(contract)],
            (None, Some(config)) => vec![Update::Config(config)],
            (None, None) => return None,
        };

        let id = UpdateId::from(self.next_id);
        self.next_id += 1;

        self.updates.insert(id, updates);
        self.votes.insert(id, HashSet::new());

        Some(id)
    }

    /// Vote for the update with the given id.
    ///
    /// Returns Some(votes) if the given [`UpdateId`] exists, otherwise None.
    pub fn vote(&mut self, id: &UpdateId, voter: AccountId) -> Option<&HashSet<AccountId>> {
        let votes = self.votes.get_mut(id)?;
        votes.insert(voter);
        Some(votes)
    }

    pub fn remove(&mut self, id: &UpdateId) -> Option<Vec<Update>> {
        self.votes.remove(id);
        self.updates.remove(id)
    }

    pub fn do_update(&mut self, id: &UpdateId, config_callback: &str, gas: Gas) -> Option<Promise> {
        let updates = self.remove(id)?;

        let mut promise = Promise::new(env::current_account_id());
        for update in updates {
            match update {
                Update::Config(config) => {
                    promise = promise.function_call(
                        config_callback.into(),
                        serde_json::to_vec(&(&config,)).unwrap(),
                        NearToken::from_near(0),
                        gas,
                    );
                }
                Update::Contract(code) => promise = promise.deploy_contract(code),
            }
        }
        Some(promise)
    }
}
