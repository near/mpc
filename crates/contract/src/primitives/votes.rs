use near_sdk::log;
use std::collections::BTreeMap;

/// Generic vote collection: each voter maps to exactly one proposal.
///
/// Methods handle vote replacement, counting (optionally filtered to valid voters),
/// and cleanup. Threshold checking remains at the call site.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema, schemars::JsonSchema)
)]
pub struct Votes<V: Ord, P> {
    pub(crate) proposal_by_voter: BTreeMap<V, P>,
}

impl<V: Ord, P> Default for Votes<V, P> {
    fn default() -> Self {
        Self {
            proposal_by_voter: BTreeMap::new(),
        }
    }
}

impl<V: Ord + Clone, P: PartialEq + Clone> Votes<V, P> {
    /// Cast or replace a vote. Returns the total number of voters who have
    /// voted for the same proposal (including this vote).
    pub fn vote(&mut self, voter: V, proposal: P) -> u64 {
        if self
            .proposal_by_voter
            .insert(voter, proposal.clone())
            .is_some()
        {
            log!("removed old vote for signer");
        }
        self.proposal_by_voter
            .values()
            .filter(|p| *p == &proposal)
            .count() as u64
    }

    /// Count votes for `proposal`, only counting voters where `is_valid_voter` returns true.
    pub fn count_where(&self, proposal: &P, is_valid_voter: impl Fn(&V) -> bool) -> u64 {
        self.proposal_by_voter
            .iter()
            .filter(|(voter, prop)| is_valid_voter(voter) && *prop == proposal)
            .count() as u64
    }

    /// Remove a specific voter's vote.
    pub fn remove_voter(&mut self, voter: &V) -> Option<P> {
        self.proposal_by_voter.remove(voter)
    }

    /// Clear all votes.
    pub fn clear(&mut self) {
        self.proposal_by_voter.clear();
    }

    /// Remove votes from voters not satisfying `predicate`.
    pub fn retain(&mut self, predicate: impl Fn(&V) -> bool) {
        self.proposal_by_voter.retain(|voter, _| predicate(voter));
    }
}

/// Votes for ThresholdParameters (new participants and threshold).
pub type ThresholdParametersVotes =
    Votes<super::key_state::AuthenticatedAccountId, super::thresholds::ThresholdParameters>;

#[cfg(test)]
mod tests {
    use super::Votes;
    use crate::primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        test_utils::{gen_participant, gen_threshold_params},
        thresholds::ThresholdParameters,
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    type ThresholdParametersVotes = Votes<AuthenticatedAccountId, ThresholdParameters>;

    fn count_participant_votes(
        votes: &ThresholdParametersVotes,
        proposal: &ThresholdParameters,
        participants: &Participants,
    ) -> u64 {
        votes.count_where(proposal, |voter| {
            participants
                .participants()
                .iter()
                .any(|(acc_id, _, _)| voter.get() == acc_id)
        })
    }

    #[test]
    fn test_voting_and_removal() {
        let mut participants = Participants::default();
        let p0 = gen_participant(0);
        participants.insert(p0.0.clone(), p0.1).expect("error");
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(p0.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        let params = gen_threshold_params(30);
        let mut votes = ThresholdParametersVotes::default();
        assert_eq!(votes.vote(participant.clone(), params.clone()), 1);
        assert_eq!(count_participant_votes(&votes, &params, &participants), 1);
        let params2 = gen_threshold_params(30);
        assert_eq!(votes.vote(participant, params2.clone()), 1);
        assert_eq!(count_participant_votes(&votes, &params2, &participants), 1);
        assert_eq!(count_participant_votes(&votes, &params, &participants), 0);

        // new participant
        let p1 = gen_participant(1);
        participants.insert(p1.0.clone(), p1.1).expect("error");
        ctx.signer_account_id(p1.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        assert_eq!(votes.vote(participant.clone(), params.clone()), 1);
        assert_eq!(count_participant_votes(&votes, &params2, &participants), 1);
        assert_eq!(votes.vote(participant, params2.clone()), 2);
        assert_eq!(count_participant_votes(&votes, &params2, &participants), 2);
        assert_eq!(
            count_participant_votes(&votes, &params2, params2.participants()),
            0
        );
        assert_eq!(count_participant_votes(&votes, &params, &participants), 0);
    }

    #[test]
    fn test_non_participant_votes_not_counted() {
        // given: two participants vote for a proposal
        let mut old_participants = Participants::default();
        let (p0, p1) = (gen_participant(0), gen_participant(1));
        old_participants
            .insert(p0.0.clone(), p0.1.clone())
            .unwrap();
        old_participants
            .insert(p1.0.clone(), p1.1.clone())
            .unwrap();

        let mut ctx = VMContextBuilder::new();
        let auth_p0 = {
            ctx.signer_account_id(p0.0);
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&old_participants).unwrap()
        };
        let auth_p1 = {
            ctx.signer_account_id(p1.0);
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&old_participants).unwrap()
        };

        let params = gen_threshold_params(30);
        let mut votes = ThresholdParametersVotes::default();
        votes.vote(auth_p0, params.clone());
        votes.vote(auth_p1, params.clone());
        assert_eq!(
            count_participant_votes(&votes, &params, &old_participants),
            2
        );

        // when: checking votes against a different participant set (simulating post-resharing)
        let mut new_participants = Participants::default();
        let p2 = gen_participant(2);
        new_participants.insert(p2.0.clone(), p2.1).unwrap();

        // then: votes from non-participants are not counted
        assert_eq!(
            count_participant_votes(&votes, &params, &new_participants),
            0
        );

        ctx.signer_account_id(p2.0);
        testing_env!(ctx.build());
        let auth_p2 = AuthenticatedAccountId::new(&new_participants).unwrap();
        votes.vote(auth_p2, params.clone());
        assert_eq!(
            count_participant_votes(&votes, &params, &new_participants),
            1
        );
    }

    #[test]
    fn test_retain() {
        let mut votes: Votes<u32, String> = Votes::default();
        votes.vote(1, "a".to_string());
        votes.vote(2, "b".to_string());
        votes.vote(3, "a".to_string());

        votes.retain(|v| *v != 2);
        assert_eq!(votes.proposal_by_voter.len(), 2);
        assert!(votes.proposal_by_voter.contains_key(&1));
        assert!(!votes.proposal_by_voter.contains_key(&2));
        assert!(votes.proposal_by_voter.contains_key(&3));
    }

    #[test]
    fn test_clear() {
        let mut votes: Votes<u32, String> = Votes::default();
        votes.vote(1, "a".to_string());
        votes.vote(2, "b".to_string());
        votes.clear();
        assert!(votes.proposal_by_voter.is_empty());
    }

    #[test]
    fn test_remove_voter() {
        let mut votes: Votes<u32, String> = Votes::default();
        votes.vote(1, "a".to_string());
        votes.vote(2, "b".to_string());

        let removed = votes.remove_voter(&1);
        assert_eq!(removed, Some("a".to_string()));
        assert_eq!(votes.proposal_by_voter.len(), 1);

        let removed = votes.remove_voter(&99);
        assert_eq!(removed, None);
    }

    #[test]
    fn test_count_where() {
        let mut votes: Votes<u32, String> = Votes::default();
        votes.vote(1, "a".to_string());
        votes.vote(2, "a".to_string());
        votes.vote(3, "b".to_string());
        votes.vote(4, "a".to_string());

        // Count all "a" votes from voters in {1, 2, 3}
        let count = votes.count_where(&"a".to_string(), |v| *v <= 3);
        assert_eq!(count, 2);

        // Count all "a" votes (no filter)
        let count = votes.count_where(&"a".to_string(), |_| true);
        assert_eq!(count, 3);
    }
}
