//! Contract updates: voting for update hashes, and applying the payload they approve.

use crate::{
    config::Config,
    dto_mapping::IntoInterfaceType,
    errors::Error,
    primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        proposal_hash::{Json, ProposalHash, Sha256, ToProposalHash},
        thresholds::GovernanceThresholdParameters,
        votes::Votes,
    },
    storage_keys::StorageKey,
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{Gas, NearToken, Promise, env, near};
use std::collections::{BTreeMap, BTreeSet};

impl ToProposalHash for dtos::UpdateHash {
    type Serializer = Json;
    type Hasher = Sha256;
}

/// Config updates run with the gas the new config prescribes, not `gas`.
pub(crate) fn update_promise(update: dtos::Update, gas: Gas) -> Result<Promise, Error> {
    let promise = Promise::new(env::current_account_id());
    Ok(match update {
        dtos::Update::Code(code) => promise.deploy_contract(code).function_call(
            method_names::MIGRATE,
            Vec::new(),
            NearToken::from_near(0),
            gas,
        ),
        dtos::Update::Config(config) => {
            let config: Config = config.try_into()?;
            let gas = Gas::from_tgas(config.contract_upgrade_deposit_tera_gas);
            promise.function_call(
                method_names::UPDATE_CONFIG,
                serde_json::to_vec(&(&config.into_dto_type(),)).expect("Config serializes to JSON"),
                NearToken::from_near(0),
                gas,
            )
        }
    })
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct ContractUpdateVotes {
    pending: Votes<AuthenticatedAccountId>,
}

impl Default for ContractUpdateVotes {
    fn default() -> Self {
        Self {
            pending: Votes::new(
                StorageKey::ContractUpdateVotesByVoter,
                StorageKey::ContractUpdateVotesByProposal,
            ),
        }
    }
}

impl ContractUpdateVotes {
    /// Replaces any earlier vote by `voter`. Returns whether `update_hash` is now approved.
    pub fn vote(
        &mut self,
        update_hash: &dtos::UpdateHash,
        voter: AuthenticatedAccountId,
        threshold_parameters: &GovernanceThresholdParameters,
    ) -> bool {
        let count = self
            .pending
            .vote(voter, update_hash.to_proposal_hash())
            .count_participants(threshold_parameters.participants());
        count >= threshold_parameters.threshold().value()
    }

    /// Clears every vote if `update_hash` is approved: votes for other hashes were cast against
    /// the superseded contract.
    pub fn take_if_approved(
        &mut self,
        update_hash: &dtos::UpdateHash,
        threshold_parameters: &GovernanceThresholdParameters,
    ) -> bool {
        let approved = self
            .pending
            .voters_for(&update_hash.to_proposal_hash())
            .is_some_and(|voters| {
                voters.count_participants(threshold_parameters.participants())
                    >= threshold_parameters.threshold().value()
            });
        if !approved {
            return false;
        }
        self.pending.clear();
        true
    }

    pub fn remove_vote(&mut self, voter: &AuthenticatedAccountId) {
        self.pending.remove_vote(voter);
    }

    pub fn retain(&mut self, current: &Participants) {
        self.pending
            .retain_votes(|voter| current.is_participant(voter));
    }

    pub fn pending(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>> {
        self.pending.all()
    }
}
