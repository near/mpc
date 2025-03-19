use super::key_state::AuthenticatedParticipantId;
use super::thresholds::ThresholdParameters;
use near_sdk::{log, near};
use std::collections::BTreeMap;

#[near(serializers=[borsh, json])]
#[derive(Debug, Default, PartialEq)]
pub struct ThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, ThresholdParameters>,
}

impl ThresholdParametersVotes {
    /// Registers a vote by `participant` for `proposal` (inserts `proposal` if necessary).
    /// Removes any existing votes by `participant`.
    /// Returns an Error if `participant` already registered a vote.
    /// Returns the number of votes for the current proposal.
    pub fn vote(
        &mut self,
        proposal: &ThresholdParameters,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant.clone(), proposal.clone())
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

#[cfg(test)]
mod tests {
    use super::ThresholdParametersVotes;
    use crate::primitives::key_state::AuthenticatedParticipantId;
    use crate::primitives::test_utils::gen_threshold_params;
    use rand::Rng;
    use std::mem;

    #[test]
    fn test_voting_and_removal() {
        let id: u64 = rand::thread_rng().gen();
        let participant: AuthenticatedParticipantId = unsafe { mem::transmute_copy(&id) };
        let mut votes = ThresholdParametersVotes::default();
        let params = gen_threshold_params(30);
        assert_eq!(votes.vote(&params, &participant), 1);
        assert_eq!(votes.vote(&params, &participant), 1);
        let participant: AuthenticatedParticipantId = unsafe { mem::transmute_copy(&(id + 1)) };
        assert_eq!(votes.vote(&params, &participant), 2);
    }
}
