use crate::primitives::proposal_hash::{Borsh, Sha256, ToProposalHash};
use crate::primitives::thresholds::ProposedGovernanceThresholdParameters;
use crate::primitives::votes::Votes;
use crate::primitives::{
    key_state::AuthenticatedAccountId,
    participants::{ParticipantCount, Participants},
};
use crate::storage_keys::StorageKey;
use near_sdk::near;

impl ToProposalHash for ProposedGovernanceThresholdParameters {
    type Serializer = Borsh;
    type Hasher = Sha256;
}

/// Votes on proposed threshold parameters, one per account, stored by proposal hash.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct GovernanceThresholdParametersVotes(Votes<AuthenticatedAccountId>);

impl Default for GovernanceThresholdParametersVotes {
    fn default() -> Self {
        Self(Votes::new(
            StorageKey::ParametersVotesByVoter,
            StorageKey::ParametersVotesByProposal,
        ))
    }
}

impl GovernanceThresholdParametersVotes {
    /// return the number of votes for `proposal` cast by members of `participants`
    pub fn n_votes(
        &self,
        proposal: &ProposedGovernanceThresholdParameters,
        participants: &Participants,
    ) -> ParticipantCount {
        self.0
            .voters_for(&proposal.to_proposal_hash())
            .map_or(ParticipantCount::new(0), |voters| {
                voters.count_participants(participants)
            })
    }

    /// Registers a vote by `participant` for `proposal`, replacing any existing vote by
    /// `participant`. Returns `true` once every proposed participant voted for `proposal`;
    /// all pending votes are then cleared.
    pub fn vote(
        &mut self,
        proposal: &ProposedGovernanceThresholdParameters,
        participant: AuthenticatedAccountId,
    ) -> bool {
        let proposed_participants = proposal.participants();
        let n_votes = self
            .0
            .vote(participant, proposal.to_proposal_hash())
            .count_participants(proposed_participants);
        let accepted = n_votes == proposed_participants.count();
        if accepted {
            self.clear();
        }
        accepted
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.0.all().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::GovernanceThresholdParametersVotes;
    use crate::primitives::{
        key_state::AuthenticatedAccountId,
        participants::{ParticipantCount, Participants},
        test_utils::{
            authenticate_account_as, gen_participant, gen_participants,
            gen_proposed_threshold_params,
        },
        thresholds::{
            GovernanceThreshold, GovernanceThresholdParameters,
            ProposedGovernanceThresholdParameters,
        },
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
        let params = gen_proposed_threshold_params(30);
        let mut votes = GovernanceThresholdParametersVotes::default();
        assert!(!votes.vote(&params, participant.clone()));
        assert_eq!(
            votes.n_votes(&params, &participants),
            ParticipantCount::new(1)
        );
        let params2 = gen_proposed_threshold_params(30);
        assert!(!votes.vote(&params2, participant));
        assert_eq!(
            votes.n_votes(&params2, &participants),
            ParticipantCount::new(1)
        );
        assert_eq!(
            votes.n_votes(&params, &participants),
            ParticipantCount::new(0)
        );

        // new participant
        let p1 = gen_participant(1);
        participants.insert(p1.0.clone(), p1.1).expect("error");
        ctx.signer_account_id(p1.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        assert!(!votes.vote(&params, participant.clone()));
        assert_eq!(
            votes.n_votes(&params2, &participants),
            ParticipantCount::new(1)
        );
        assert!(!votes.vote(&params2, participant));
        assert_eq!(
            votes.n_votes(&params2, &participants),
            ParticipantCount::new(2)
        );
        assert_eq!(
            votes.n_votes(&params2, params2.participants()),
            ParticipantCount::new(0)
        );
        assert_eq!(
            votes.n_votes(&params, &participants),
            ParticipantCount::new(0)
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_tally_distinct_per_domain_threshold_updates_separately() {
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

        let base = gen_proposed_threshold_params(30);
        let mut updates_a = BTreeMap::new();
        updates_a.insert(DomainId(0), ReconstructionThreshold::new(2));
        let mut updates_b = BTreeMap::new();
        updates_b.insert(DomainId(0), ReconstructionThreshold::new(3));
        let proposal_a = base.clone().with_per_domain_thresholds(updates_a);
        let proposal_b = base.with_per_domain_thresholds(updates_b);

        // When each voter casts a different proposal
        let mut votes = GovernanceThresholdParametersVotes::default();
        votes.vote(&proposal_a, auth_p0);
        votes.vote(&proposal_b, auth_p1);

        // Then the two proposals are tallied independently
        assert_eq!(
            votes.n_votes(&proposal_a, &participants),
            ParticipantCount::new(1)
        );
        assert_eq!(
            votes.n_votes(&proposal_b, &participants),
            ParticipantCount::new(1)
        );
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

        let params = gen_proposed_threshold_params(30);
        let mut votes = GovernanceThresholdParametersVotes::default();
        votes.vote(&params, auth_p0);
        votes.vote(&params, auth_p1);
        assert_eq!(
            votes.n_votes(&params, &old_participants),
            ParticipantCount::new(2)
        );

        // when: checking votes against a different participant set (simulating post-resharing)
        let mut new_participants = Participants::default();
        let p2 = gen_participant(2);
        new_participants.insert(p2.0.clone(), p2.1).unwrap();

        // then: votes from non-participants are not counted
        assert_eq!(
            votes.n_votes(&params, &new_participants),
            ParticipantCount::new(0)
        );

        ctx.signer_account_id(p2.0);
        testing_env!(ctx.build());
        let auth_p2 = AuthenticatedAccountId::new(&new_participants).unwrap();
        votes.vote(&params, auth_p2);
        assert_eq!(
            votes.n_votes(&params, &new_participants),
            ParticipantCount::new(1)
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_accept_and_clear_votes_once_all_proposed_participants_voted() {
        // Given: a fourth participant holds a vote for a different proposal
        let participants = gen_participants(4);
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(
                participants.subset(0..3),
                GovernanceThreshold::new(2),
            )
            .unwrap(),
            BTreeMap::new(),
        );
        let other_proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants.clone(), GovernanceThreshold::new(3))
                .unwrap(),
            BTreeMap::new(),
        );
        let voters: Vec<AuthenticatedAccountId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| authenticate_account_as(account_id, &participants))
            .collect();
        let mut votes = GovernanceThresholdParametersVotes::default();
        assert!(!votes.vote(&other_proposal, voters[3].clone()));
        assert!(!votes.vote(&proposal, voters[0].clone()));
        assert!(!votes.vote(&proposal, voters[1].clone()));

        // When
        let accepted = votes.vote(&proposal, voters[2].clone());

        // Then
        assert!(accepted);
        assert!(votes.is_empty());
    }
}
