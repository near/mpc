use super::foreign_chain::ForeignChainPolicy;
use super::key_state::AuthenticatedAccountId;
use super::participants::Participants;
use near_sdk::{log, near};
use std::collections::BTreeMap;

/// Tracks votes for ForeignChainPolicy changes.
/// Each current participant can maintain one vote at a time.
/// Follows the same pattern as ThresholdParametersVotes.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForeignChainPolicyVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, ForeignChainPolicy>,
}

impl ForeignChainPolicyVotes {
    /// Returns the number of votes for `proposal` cast by members of `participants`
    pub fn n_votes(&self, proposal: &ForeignChainPolicy, participants: &Participants) -> u64 {
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
    /// Returns the number of participants who have voted for the same proposal
    /// (including the new vote).
    pub fn vote(
        &mut self,
        proposal: &ForeignChainPolicy,
        participant: AuthenticatedAccountId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant, proposal.clone())
            .is_some()
        {
            log!("removed old vote for foreign chain policy");
        }
        self.proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64
    }

    /// Get all unique proposals with their vote counts from the given participants.
    /// Returns a vector of (proposal, vote_count) pairs.
    pub fn get_proposals_with_counts(
        &self,
        participants: &Participants,
    ) -> Vec<(ForeignChainPolicy, u64)> {
        let mut proposal_counts: BTreeMap<ForeignChainPolicy, u64> = BTreeMap::new();

        for (acc, proposal) in &self.proposal_by_account {
            // Only count votes from current participants
            let is_participant = participants
                .participants()
                .iter()
                .any(|(acc_id, _, _)| acc.get() == acc_id);

            if is_participant {
                *proposal_counts.entry(proposal.clone()).or_insert(0) += 1;
            }
        }

        proposal_counts.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::ForeignChainPolicyVotes;
    use crate::primitives::{
        foreign_chain::{ForeignChain, ForeignChainEntry, ForeignChainPolicy, RpcProviderName},
        key_state::AuthenticatedAccountId,
        participants::Participants,
        test_utils::gen_participant,
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use utilities::AccountIdExtV2;

    fn gen_policy(providers: Vec<&str>) -> ForeignChainPolicy {
        ForeignChainPolicy::new(vec![ForeignChainEntry::new(
            ForeignChain::Solana,
            providers.into_iter().map(RpcProviderName::new).collect(),
        )])
    }

    #[test]
    fn test_voting_and_replacement() {
        let mut participants = Participants::default();
        let p0 = gen_participant(0);
        participants.insert(p0.0.clone(), p0.1).expect("error");
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(p0.0.as_v1_account_id());
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");

        let policy1 = gen_policy(vec!["alchemy"]);
        let mut votes = ForeignChainPolicyVotes::default();

        // First vote
        assert_eq!(votes.vote(&policy1, participant.clone()), 1);
        assert_eq!(votes.n_votes(&policy1, &participants), 1);

        // Replace vote with different policy
        let policy2 = gen_policy(vec!["quicknode"]);
        assert_eq!(votes.vote(&policy2, participant), 1);
        assert_eq!(votes.n_votes(&policy2, &participants), 1);
        assert_eq!(votes.n_votes(&policy1, &participants), 0);
    }

    #[test]
    fn test_multiple_participants_voting() {
        let mut participants = Participants::default();
        let (p0, p1) = (gen_participant(0), gen_participant(1));
        participants.insert(p0.0.clone(), p0.1.clone()).unwrap();
        participants.insert(p1.0.clone(), p1.1.clone()).unwrap();

        let mut ctx = VMContextBuilder::new();
        let auth_p0 = {
            ctx.signer_account_id(p0.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };
        let auth_p1 = {
            ctx.signer_account_id(p1.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };

        let policy = gen_policy(vec!["alchemy"]);
        let mut votes = ForeignChainPolicyVotes::default();

        // Both participants vote for the same policy
        votes.vote(&policy, auth_p0);
        votes.vote(&policy, auth_p1);
        assert_eq!(votes.n_votes(&policy, &participants), 2);
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
            ctx.signer_account_id(p0.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&old_participants).unwrap()
        };
        let auth_p1 = {
            ctx.signer_account_id(p1.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&old_participants).unwrap()
        };

        let policy = gen_policy(vec!["alchemy"]);
        let mut votes = ForeignChainPolicyVotes::default();
        votes.vote(&policy, auth_p0);
        votes.vote(&policy, auth_p1);
        assert_eq!(votes.n_votes(&policy, &old_participants), 2);

        // when: checking votes against a different participant set (simulating post-resharing)
        let mut new_participants = Participants::default();
        let p2 = gen_participant(2);
        new_participants.insert(p2.0.clone(), p2.1).unwrap();

        // then: votes from non-participants are not counted
        assert_eq!(votes.n_votes(&policy, &new_participants), 0);

        ctx.signer_account_id(p2.0.as_v1_account_id());
        testing_env!(ctx.build());
        let auth_p2 = AuthenticatedAccountId::new(&new_participants).unwrap();
        votes.vote(&policy, auth_p2);
        assert_eq!(votes.n_votes(&policy, &new_participants), 1);
    }

    #[test]
    fn test_get_proposals_with_counts() {
        let mut participants = Participants::default();
        let (p0, p1, p2) = (gen_participant(0), gen_participant(1), gen_participant(2));
        participants.insert(p0.0.clone(), p0.1.clone()).unwrap();
        participants.insert(p1.0.clone(), p1.1.clone()).unwrap();
        participants.insert(p2.0.clone(), p2.1.clone()).unwrap();

        let mut ctx = VMContextBuilder::new();
        let auth_p0 = {
            ctx.signer_account_id(p0.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };
        let auth_p1 = {
            ctx.signer_account_id(p1.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };
        let auth_p2 = {
            ctx.signer_account_id(p2.0.as_v1_account_id());
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&participants).unwrap()
        };

        let policy_a = gen_policy(vec!["alchemy"]);
        let policy_b = gen_policy(vec!["quicknode"]);

        let mut votes = ForeignChainPolicyVotes::default();
        votes.vote(&policy_a, auth_p0);
        votes.vote(&policy_a, auth_p1);
        votes.vote(&policy_b, auth_p2);

        let proposals = votes.get_proposals_with_counts(&participants);
        assert_eq!(proposals.len(), 2);

        // Find the counts for each policy
        let count_a = proposals
            .iter()
            .find(|(p, _)| p == &policy_a)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let count_b = proposals
            .iter()
            .find(|(p, _)| p == &policy_b)
            .map(|(_, c)| *c)
            .unwrap_or(0);

        assert_eq!(count_a, 2);
        assert_eq!(count_b, 1);
    }
}
