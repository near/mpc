//! Contract updates: participants vote for a [`dtos::UpdateHash`], and while a governance
//! threshold of them backs it, the matching [`Update`] may be submitted and applied.

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

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Update {
    Code(Vec<u8>),
    Config(Config),
}

impl TryFrom<dtos::Update> for Update {
    type Error = Error;

    fn try_from(value: dtos::Update) -> Result<Self, Self::Error> {
        Ok(match value {
            dtos::Update::Code(code) => Update::Code(code),
            dtos::Update::Config(config) => Update::Config(config.try_into()?),
        })
    }
}

impl Update {
    /// Code updates deploy the code and call `migrate` with `gas`; config updates call
    /// `update_config` with the gas the new config prescribes.
    pub fn into_promise(self, gas: Gas) -> Promise {
        let promise = Promise::new(env::current_account_id());
        match self {
            Update::Code(code) => promise.deploy_contract(code).function_call(
                method_names::MIGRATE,
                Vec::new(),
                NearToken::from_near(0),
                gas,
            ),
            Update::Config(config) => {
                let gas = Gas::from_tgas(config.contract_upgrade_deposit_tera_gas);
                let dto_config = config.into_dto_type();
                promise.function_call(
                    method_names::UPDATE_CONFIG,
                    serde_json::to_vec(&(&dto_config,)).expect("Config serializes to JSON"),
                    NearToken::from_near(0),
                    gas,
                )
            }
        }
    }
}

/// JSON so that participants can verify a pending-vote key off-chain from the hash they
/// submitted.
impl ToProposalHash for dtos::UpdateHash {
    type Serializer = Json;
    type Hasher = Sha256;
}

/// Approval is not latched: an update may be submitted exactly while its hash holds votes from
/// a governance threshold of *current* participants. Withdrawing a vote therefore un-approves
/// the hash, and so does a resharing that drops its backers.
///
/// A governance threshold always exceeds half the participants and each participant holds one
/// vote, so at most one hash is approved at a time.
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
    /// Records `voter`'s vote for `update_hash`, replacing any earlier vote of theirs. Returns
    /// whether the hash is now approved.
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

    /// Clears every vote if `update_hash` is approved, so that the caller may apply it exactly
    /// once. Votes for other hashes go too: they were cast against the superseded contract.
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

    /// Withdraws `voter`'s vote, which un-approves the hash they backed if it drops below the
    /// governance threshold.
    pub fn remove_vote(&mut self, voter: &AuthenticatedAccountId) {
        self.pending.remove_vote(voter);
    }

    /// Drops votes from accounts that are no longer participants.
    pub fn retain(&mut self, current: &Participants) {
        self.pending
            .retain_votes(|voter| current.is_participant(voter));
    }

    pub fn pending(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>> {
        self.pending.all()
    }
}

#[cfg(test)]
mod tests {
    use crate::update::Update;
    use near_mpc_contract_interface::types as dtos;
    use test_utils::contract_types::dummy_config;

    // Vote bookkeeping is covered by `primitives::votes`, approval by `api::update`.
    #[test]
    #[expect(non_snake_case)]
    fn update_try_from__should_reject_invalid_config() {
        // Given a config whose launcher TTL is below the attestation validity window.
        let mut config = dummy_config(1);
        config.launcher_hash_unused_ttl_seconds = 0;

        // When it is converted into an `Update`.
        let result = Update::try_from(dtos::Update::Config(config));

        // Then it is rejected before it can be applied.
        let err = result.expect_err("invalid config must be rejected");
        assert!(
            format!("{err:?}").contains("launcher_hash_unused_ttl_seconds"),
            "error should point at the invalid field, got: {err:?}"
        );
    }
}
