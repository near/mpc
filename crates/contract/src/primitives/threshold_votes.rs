use crate::primitives::thresholds::ProposedThresholdParameters;
use crate::primitives::{key_state::AuthenticatedAccountId, participants::Participants};
use near_sdk::{log, near};
use std::collections::BTreeMap;

/// Tracks votes for ThresholdParameters (new participants and threshold).
/// Each current participant can maintain one vote.
// TODO(#2825): Replace with Votes<AuthenticatedAccountId> from votes.rs
// once this type is moved out of RunningContractState (which requires Clone + PartialEq + JSON).
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThresholdParametersVotes {
    pub(crate) proposal_by_account: BTreeMap<AuthenticatedAccountId, ProposedThresholdParameters>,
}

impl ThresholdParametersVotes {
    /// return the number of votes for `proposal` cast by members of `participants`
    pub fn n_votes(
        &self,
        proposal: &ProposedThresholdParameters,
        participants: &Participants,
    ) -> u64 {
        u64::try_from(
            self.proposal_by_account
                .iter()
                .filter(|&(acc, prop)| {
                    participants
                        .participants()
                        .iter()
                        .any(|(acc_id, _, _)| acc.get() == acc_id)
                        && prop == proposal
                })
                .count(),
        )
        .expect("usize should never fail to convert to u64 on wasm32")
    }
    /// Registers a vote by `participant` for `proposal`.
    /// Removes any existing votes by `participant`.
    /// Returns the number of participants who have voted for the same proposal (including the new
    /// vote).
    pub fn vote(
        &mut self,
        proposal: &ProposedThresholdParameters,
        participant: AuthenticatedAccountId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant, proposal.clone())
            .is_some()
        {
            log!("removed one vote for signer");
        }
        u64::try_from(
            self.proposal_by_account
                .values()
                .filter(|&prop| prop == proposal)
                .count(),
        )
        .expect("usize should never fail to convert on u64 on wasm32")
    }
}

#[cfg(test)]
mod tests {
    use super::ThresholdParametersVotes;
    use crate::primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        test_utils::{gen_participant, gen_threshold_params},
    };
    use near_mpc_contract_interface::types::{DomainId, ReconstructionThreshold};
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use std::collections::BTreeMap;

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
        assert_eq!(votes.vote(&params, participant.clone()), 1);
        assert_eq!(votes.n_votes(&params, &participants), 1);
        let params2 = gen_threshold_params(30);
        assert_eq!(votes.vote(&params2, participant), 1);
        assert_eq!(votes.n_votes(&params2, &participants), 1);
        assert_eq!(votes.n_votes(&params, &participants), 0);

        // new participant
        let p1 = gen_participant(1);
        participants.insert(p1.0.clone(), p1.1).expect("error");
        ctx.signer_account_id(p1.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        assert_eq!(votes.vote(&params, participant.clone()), 1);
        assert_eq!(votes.n_votes(&params2, &participants), 1);
        assert_eq!(votes.vote(&params2, participant), 2);
        assert_eq!(votes.n_votes(&params2, &participants), 2);
        assert_eq!(votes.n_votes(&params2, params2.participants()), 0);
        assert_eq!(votes.n_votes(&params, &participants), 0);
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_tally_distinct_per_domain_overlays_separately() {
        // Given two voters and two proposals identical except for per_domain_thresholds
        let mut participants = Participants::default();
        let (p0, p1) = (gen_participant(0), gen_participant(1));
        participants.insert(p0.0.clone(), p0.1).unwrap();
        participants.insert(p1.0.clone(), p1.1).unwrap();

        let mut ctx = VMContextBuilder::new();
        let auth_p0 = {
            ctx.signer_account_id(p0.0);
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };
        let auth_p1 = {
            ctx.signer_account_id(p1.0);
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };

        let base = gen_threshold_params(30);
        let mut overlay_a = BTreeMap::new();
        overlay_a.insert(DomainId(0), ReconstructionThreshold::new(2));
        let mut overlay_b = BTreeMap::new();
        overlay_b.insert(DomainId(0), ReconstructionThreshold::new(3));
        let proposal_a = base.clone().with_per_domain_thresholds(overlay_a);
        let proposal_b = base.with_per_domain_thresholds(overlay_b);

        // When each voter casts a different overlay
        let mut votes = ThresholdParametersVotes::default();
        votes.vote(&proposal_a, auth_p0);
        votes.vote(&proposal_b, auth_p1);

        // Then the two proposals are tallied independently
        assert_eq!(votes.n_votes(&proposal_a, &participants), 1);
        assert_eq!(votes.n_votes(&proposal_b, &participants), 1);
    }

    #[test]
    fn test_non_participant_votes_not_counted() {
        // given: two participants vote for a proposal
        let mut old_participants = Participants::default();
        let (p0, p1) = (gen_participant(0), gen_participant(1));
        old_participants.insert(p0.0.clone(), p0.1.clone()).unwrap();
        old_participants.insert(p1.0.clone(), p1.1.clone()).unwrap();

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
        votes.vote(&params, auth_p0);
        votes.vote(&params, auth_p1);
        assert_eq!(votes.n_votes(&params, &old_participants), 2);

        // when: checking votes against a different participant set (simulating post-resharing)
        let mut new_participants = Participants::default();
        let p2 = gen_participant(2);
        new_participants.insert(p2.0.clone(), p2.1).unwrap();

        // then: votes from non-participants are not counted
        assert_eq!(votes.n_votes(&params, &new_participants), 0);

        ctx.signer_account_id(p2.0);
        testing_env!(ctx.build());
        let auth_p2 = AuthenticatedAccountId::new(&new_participants).unwrap();
        votes.vote(&params, auth_p2);
        assert_eq!(votes.n_votes(&params, &new_participants), 1);
    }
}
