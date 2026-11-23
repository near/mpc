use crate::primitives::key_state::AuthenticatedAccountId;
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
        participants::Participants,
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

    /// Had `first` kept its vote for `proposal`, the vote of `second` would meet the threshold.
    #[test]
    #[expect(non_snake_case)]
    fn vote__should_replace_the_voters_previous_vote() {
        // Given
        let current =
            GovernanceThresholdParameters::new(gen_participants(3), GovernanceThreshold::new(2))
                .unwrap();
        let mut voters = threshold_voters(&current)
            .into_iter()
            .map(|account_id| authenticate_account_as(&account_id, current.participants()));
        let first = voters.next().unwrap();
        let second = voters.next().unwrap();
        let proposal = gen_proposed_threshold_params(30);
        let other_proposal = gen_proposed_threshold_params(proposal.participants().len());
        let mut votes = GovernanceThresholdParametersVotes::default();

        // When
        let accepted = [
            votes.vote(&proposal, first.clone(), &current),
            votes.vote(&other_proposal, first, &current),
            votes.vote(&proposal, second, &current),
        ];

        // Then
        assert_eq!(accepted, [false, false, false]);
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_tally_distinct_per_domain_threshold_updates_separately() {
        // Given
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
        let current =
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
        let mut votes = GovernanceThresholdParametersVotes::default();

        // When
        let accepted = [
            votes.vote(&proposal_a, auth_p0, &current),
            votes.vote(&proposal_b, auth_p1, &current),
        ];

        // Then
        assert_eq!(accepted, [false, false]);
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_not_count_votes_from_former_participants() {
        // Given
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

        let mut new_participants = Participants::default();
        let (p2, p3) = (gen_participant(2), gen_participant(3));
        new_participants.insert(p2.0.clone(), p2.1).unwrap();
        new_participants.insert(p3.0, p3.1).unwrap();
        let current =
            GovernanceThresholdParameters::new(new_participants, GovernanceThreshold::new(2))
                .unwrap();
        ctx.signer_account_id(p2.0);
        testing_env!(ctx.build());
        let auth_p2 = AuthenticatedAccountId::new(current.participants()).unwrap();

        // When
        let accepted = votes.vote(&params, auth_p2, &current);

        // Then
        assert!(!accepted);
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
