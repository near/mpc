use super::{code_hash::CodeHash, key_state::AuthenticatedAccountId, participants::Participants};
use near_sdk::{log, near};
use std::collections::BTreeMap;

/// Tracks votes for Docker images. Each current participant can maintain one vote.
#[near(serializers=[borsh, json])]
#[derive(Debug, Default, PartialEq)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, CodeHash>,
}

impl ThresholdParametersVotes {
    /// return the number of votes for `proposal` casted by members of `participants`
    pub fn n_votes(&self, proposal: &CodeHash, participants: &Participants) -> u64 {
        self.proposal_by_account
            .iter()
            .filter(|&(acc, prop)| {
                participants
                    .participants()
                    .iter()
                    .any(|(acc_id, _, _)| acc.get() == acc_id)
                    && prop == proposal
            })
            .count() as u64
    }
    /// Registers a vote by `participant` for `proposal`.
    /// Removes any existing votes by `participant`.
    /// Returns the number of participants who have voted for the same proposal (including the new
    /// vote).
    pub fn vote(&mut self, proposal: &CodeHash, participant: AuthenticatedAccountId) -> u64 {
        if self
            .proposal_by_account
            .insert(participant, proposal.clone())
            .is_some()
        {
            log!("removed one vote for signer");
        }
        self.proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64
    }
}
