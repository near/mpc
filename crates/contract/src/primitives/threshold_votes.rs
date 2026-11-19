use crate::primitives::key_state::AuthenticatedAccountId;
#[cfg(test)]
use crate::primitives::participants::{ParticipantCount, Participants};
use crate::primitives::proposal_hash::{Borsh, ProposalHash, Sha256, ToProposalHash};
use crate::primitives::thresholds::{
    GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
};
use crate::primitives::votes::Votes;
use crate::storage_keys::StorageKey;
use near_sdk::near;
use std::collections::{BTreeMap, BTreeSet};

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
    #[cfg(test)]
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
    /// `participant`. Returns `true` once the participants of `current` who voted for
    /// `proposal` meet its governance threshold.
    pub fn vote(
        &mut self,
        proposal: &ProposedGovernanceThresholdParameters,
        participant: AuthenticatedAccountId,
        current: &GovernanceThresholdParameters,
    ) -> bool {
        let n_votes = self
            .0
            .vote(participant, proposal.to_proposal_hash())
            .count_participants(current.participants());
        current.threshold().is_met_by(n_votes)
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn all(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>> {
        self.0.all()
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
        thresholds::{GovernanceThreshold, GovernanceThresholdParameters},
    };
    use crate::state::test_utils::threshold_voters;
    use near_mpc_contract_interface::types::{DomainId, ReconstructionThreshold};
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use std::collections::BTreeMap;

    /// Above the number of votes any test in this module casts against `never_accepting`.
    const UNREACHED_GOVERNANCE_THRESHOLD: u64 = 3;

    /// `participants` under `UNREACHED_GOVERNANCE_THRESHOLD`, so no proposal is accepted.
    fn never_accepting(participants: &Participants) -> GovernanceThresholdParameters {
        GovernanceThresholdParameters::new_unvalidated(
            participants.clone(),
            GovernanceThreshold::new(UNREACHED_GOVERNANCE_THRESHOLD),
        )
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
        let params = gen_proposed_threshold_params(30);
        let mut votes = GovernanceThresholdParametersVotes::default();
        votes.vote(
            &params,
            participant.clone(),
            &never_accepting(&participants),
        );
        assert_eq!(
            votes.n_votes(&params, &participants),
            ParticipantCount::new(1)
        );
        let params2 = gen_proposed_threshold_params(30);
        votes.vote(&params2, participant, &never_accepting(&participants));
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
        votes.vote(
            &params,
            participant.clone(),
            &never_accepting(&participants),
        );
        assert_eq!(
            votes.n_votes(&params2, &participants),
            ParticipantCount::new(1)
        );
        votes.vote(&params2, participant, &never_accepting(&participants));
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
        votes.vote(&proposal_a, auth_p0, &never_accepting(&participants));
        votes.vote(&proposal_b, auth_p1, &never_accepting(&participants));

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
        votes.vote(&params, auth_p0, &never_accepting(&old_participants));
        votes.vote(&params, auth_p1, &never_accepting(&old_participants));
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
        votes.vote(&params, auth_p2, &never_accepting(&new_participants));
        assert_eq!(
            votes.n_votes(&params, &new_participants),
            ParticipantCount::new(1)
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_accept_once_current_participants_meet_the_governance_threshold() {
        // Given
        let current =
            GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
                .unwrap();
        let proposal = gen_proposed_threshold_params(30);
        let voters: Vec<AuthenticatedAccountId> = threshold_voters(&current)
            .iter()
            .map(|account_id| authenticate_account_as(account_id, current.participants()))
            .collect();
        let mut votes = GovernanceThresholdParametersVotes::default();

        // When
        let accepted: Vec<bool> = voters
            .into_iter()
            .map(|voter| votes.vote(&proposal, voter, &current))
            .collect();

        // Then
        assert_eq!(accepted, [false, false, true]);
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_not_count_votes_from_outside_the_current_participants() {
        // Given
        let current =
            GovernanceThresholdParameters::new(gen_participants(3), GovernanceThreshold::new(2))
                .unwrap();
        let outsiders = gen_participants(current.participants().len());
        let proposal = gen_proposed_threshold_params(30);
        let mut votes = GovernanceThresholdParametersVotes::default();

        // When
        let accepted: Vec<bool> = outsiders
            .participants()
            .iter()
            .map(|(account_id, _, _)| {
                let voter = authenticate_account_as(account_id, &outsiders);
                votes.vote(&proposal, voter, &current)
            })
            .collect();

        // Then
        assert!(accepted.iter().all(|accepted| !accepted));
    }
}
