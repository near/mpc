use super::initializing::InitializingContractState;
use super::key_event::KeyEvent;
use super::resharing::ResharingContractState;
use crate::errors::{DomainError, Error, InvalidParameters, VoteError};
use crate::primitives::{
    domain::{
        AddDomainsVotes, DomainRegistry, max_reconstruction_threshold, validate_domain_purpose,
        validate_domain_threshold,
    },
    key_state::{AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, Keyset},
    threshold_votes::ThresholdParametersVotes,
    thresholds::{ProposedThresholdParameters, ThresholdParameters},
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::DomainConfig;
use near_sdk::near;
use std::collections::{BTreeSet, HashSet};

/// In this state, the contract is ready to process signature requests.
///
/// Proposals can be submitted to modify the state:
///  - vote_add_domains, upon threshold agreement, transitions into the
///    Initializing state to generate keys for new domains.
///  - vote_new_parameters, upon threshold agreement, transitions into the
///    Resharing state to reshare keys for new participants and also change the
///    threshold if desired.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningContractState {
    /// The domains for which we have a key ready for signature processing.
    pub domains: DomainRegistry,
    /// The keys that are currently in use; for each domain provides an unique identifier for a
    /// distributed key, so that the nodes can identify which local keyshare to use.
    pub keyset: Keyset,
    /// The current participants and threshold.
    pub parameters: ThresholdParameters,
    /// Votes for proposals for a new set of participants and threshold.
    pub parameters_votes: ThresholdParametersVotes,
    /// Votes for proposals to add new domains.
    pub add_domains_votes: AddDomainsVotes,
    /// The previous epoch id for a resharing state that was cancelled.
    /// This epoch id is tracked, as the next time the state transitions to resharing,
    /// we can't reuse a previously cancelled epoch id.
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl RunningContractState {
    pub fn new(
        domains: DomainRegistry,
        keyset: Keyset,
        parameters: ThresholdParameters,
        add_domains_votes: AddDomainsVotes,
    ) -> Self {
        let remaining_add_domain_votes =
            add_domains_votes.get_remaining_votes(parameters.participants());
        RunningContractState {
            domains,
            keyset,
            parameters,
            parameters_votes: ThresholdParametersVotes::default(),
            add_domains_votes: remaining_add_domain_votes,
            previously_cancelled_resharing_epoch_id: None,
        }
    }

    pub fn transition_to_resharing_no_checks(
        &mut self,
        proposal: &ProposedThresholdParameters,
    ) -> Option<ResharingContractState> {
        if let Some(first_domain) = self.domains.get_domain_by_index(0) {
            let epoch_id = self.prospective_epoch_id();

            Some(ResharingContractState {
                previous_running_state: RunningContractState::new(
                    self.domains.clone(),
                    self.keyset.clone(),
                    self.parameters.clone(),
                    self.add_domains_votes.clone(),
                ),
                reshared_keys: Vec::new(),
                resharing_key: KeyEvent::new(
                    epoch_id,
                    first_domain.clone(),
                    proposal.parameters().clone(),
                ),
                cancellation_requests: HashSet::new(),
                per_domain_thresholds: proposal.per_domain_thresholds().clone(),
            })
        } else {
            // New parameters were proposed, but we have no keys, so directly
            // transition into Running state but bump the EpochId. With no
            // domains the per-domain threshold updates have nothing to apply to
            // and are dropped.
            *self = RunningContractState::new(
                self.domains.clone(),
                Keyset::new(self.keyset.epoch_id.next(), Vec::new()),
                proposal.parameters().clone(),
                self.add_domains_votes.clone(),
            );
            None
        }
    }

    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContractState if the proposal is accepted.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: &ProposedThresholdParameters,
    ) -> Result<Option<ResharingContractState>, Error> {
        let expected_prospective_epoch_id = self.prospective_epoch_id();

        if prospective_epoch_id != expected_prospective_epoch_id {
            return Err(InvalidParameters::EpochMismatch {
                expected: expected_prospective_epoch_id,
                provided: prospective_epoch_id,
            }
            .into());
        }

        if self.process_new_parameters_proposal(proposal)? {
            return Ok(self.transition_to_resharing_no_checks(proposal));
        }
        Ok(None)
    }

    pub fn prospective_epoch_id(&self) -> EpochId {
        match self.previously_cancelled_resharing_epoch_id {
            // If `cancelled_epoch_id`, then a resharing has already
            // been attempted but was cancelled.
            // We must make sure to not reuse previously used prospective epoch ids,
            // and continue from the last prospective epoch id for the previous resharing attempt.
            Some(cancelled_epoch_id) => cancelled_epoch_id,
            // No resharing has been attempted for this running state.
            None => self.keyset.epoch_id,
        }
        .next()
    }

    /// Casts a vote for `proposal`, removing any previous votes by `env::signer_account_id()`.
    /// Fails if the proposal is invalid or the signer is not a proposed participant.
    /// Returns true if all participants of the proposed parameters voted for it.
    pub(super) fn process_new_parameters_proposal(
        &mut self,
        proposal: &ProposedThresholdParameters,
    ) -> Result<bool, Error> {
        // ensure the proposal is valid against the current parameters
        self.parameters
            .validate_incoming_proposal(proposal.parameters())?;

        // Validate effective per-domain thresholds (updates override, absent
        // domains keep theirs) against the proposed participant count.
        let new_num_participants =
            u64::try_from(proposal.participants().len()).expect("participant count fits in u64");
        let threshold_updates = proposal.per_domain_thresholds();
        // Reject unknown domain IDs: the loop below iterates existing domains, so
        // an unknown ID would otherwise be silently ignored here (it's caught at
        // the resharing transition, but we fail fast at vote acceptance).
        for id in threshold_updates.keys() {
            if self.domains.get_domain_by_domain_id(*id).is_none() {
                return Err(DomainError::UnknownDomainInProposal { domain_id: *id }.into());
            }
        }
        let effective_domains: Vec<DomainConfig> = self
            .domains
            .domains()
            .iter()
            .map(|domain| {
                let effective_threshold = threshold_updates
                    .get(&domain.id)
                    .copied()
                    .unwrap_or(domain.reconstruction_threshold);
                DomainConfig {
                    reconstruction_threshold: effective_threshold,
                    ..domain.clone()
                }
            })
            .collect();
        for domain in &effective_domains {
            validate_domain_threshold(domain, new_num_participants)?;
        }

        // The GovernanceThreshold must dominate every domain's effective ReconstructionThreshold;
        // enforced here so the state transition is self-contained (single source of truth).
        ThresholdParameters::validate_governance_against_reconstruction(
            new_num_participants,
            proposal.threshold(),
            max_reconstruction_threshold(&effective_domains),
        )?;

        // ensure the signer is a proposed participant
        let candidate = AuthenticatedAccountId::new(proposal.participants())?;

        // If the signer is not a participant of the current epoch, they can only vote after
        // `threshold` participant of the current epoch have casted their vote to admit them.
        if AuthenticatedAccountId::new(self.parameters.participants()).is_err() {
            let n_votes = self
                .parameters_votes
                .n_votes(proposal, self.parameters.participants());
            if n_votes < self.parameters.threshold().value() {
                return Err(VoteError::VoterPending.into());
            }
        }

        // finally, vote.
        let n_votes = self.parameters_votes.vote(proposal, candidate);
        Ok(new_num_participants == n_votes)
    }

    /// Casts a vote for the signer participant to add new domains, replacing any previous vote.
    /// If the number of votes for the same set of new domains reaches the number of participants,
    /// returns the InitializingContractState we should transition into to generate keys for these
    /// new domains.
    pub fn vote_add_domains(
        &mut self,
        domains: Vec<DomainConfig>,
    ) -> Result<Option<InitializingContractState>, Error> {
        if domains.is_empty() {
            return Err(DomainError::AddDomainsMustAddAtLeastOneDomain.into());
        }
        let num_participants = u64::try_from(self.parameters.participants().len())
            .expect("participant count fits in u64");
        for domain in &domains {
            validate_domain_purpose(domain)?;
            validate_domain_threshold(domain, num_participants)?;
        }
        // Keep trust assumptions consistent: a domain must never require more shares to
        // reconstruct than the GovernanceThreshold demands to govern. Route through the
        // canonical helper so the cross-domain invariant has a single source of truth.
        ThresholdParameters::validate_governance_against_reconstruction(
            num_participants,
            self.parameters.threshold(),
            max_reconstruction_threshold(&domains),
        )?;
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;
        let n_votes = self.add_domains_votes.vote(domains.clone(), &participant);
        if self.parameters.participants().len() as u64 == n_votes {
            let new_domains = self.domains.add_domains(domains.clone())?;
            Ok(Some(InitializingContractState {
                generated_keys: self.keyset.domains.clone(),
                domains: new_domains,
                epoch_id: self.keyset.epoch_id,
                generating_key: KeyEvent::new(
                    self.keyset.epoch_id,
                    domains[0].clone(),
                    self.parameters.clone(),
                ),
                cancel_votes: BTreeSet::new(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn is_participant_given_account_id(&self, account_id: &AccountId) -> bool {
        self.parameters
            .participants()
            .is_participant_given_account_id(account_id)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
pub mod running_tests {
    use rstest::rstest;

    use super::RunningContractState;
    use crate::errors::{Error, InvalidThreshold};
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::test_utils::{
        NUM_PROTOCOLS, gen_participants, gen_proposed_threshold_params,
    };
    use crate::primitives::threshold_votes::ThresholdParametersVotes;
    use crate::primitives::thresholds::{Threshold, ThresholdParameters};
    use crate::state::key_event::tests::Environment;
    use crate::state::test_utils::{
        gen_running_state, gen_running_state_with_params, gen_valid_params_proposal,
    };
    use near_mpc_contract_interface::types::{
        DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
    };

    fn test_running_for(num_domains: usize) {
        let mut state = gen_running_state(num_domains);
        println!(
            "Participants: {}, threshold: {}",
            state.parameters.participants().len(),
            state.parameters.threshold().value()
        );
        let mut env = Environment::new(None, None, None);
        let participants = state.parameters.participants().clone();
        // Assert that random proposals get rejected.
        for (account_id, _, _) in participants.participants() {
            let ksp = gen_proposed_threshold_params(30);
            env.set_signer(account_id);
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &ksp)
                .unwrap_err();
        }
        // Assert that proposals of the wrong epoch ID get rejected.
        {
            let ksp = gen_valid_params_proposal(&state.parameters);
            env.set_signer(&participants.participants()[0].0);
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id, &ksp)
                .unwrap_err();
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id.next().next(), &ksp)
                .unwrap_err();
        }
        // Assert that disagreeing proposals do not reach consensus.
        // Generate an extra proposal for the next step.
        let mut proposals = Vec::new();
        for i in 0..participants.participants().len() + 1 {
            loop {
                let proposal = gen_valid_params_proposal(&state.parameters);
                if proposals.contains(&proposal) {
                    continue;
                }
                if i < participants.participants().len()
                    && !proposal
                        .participants()
                        .is_participant_given_account_id(&participants.participants()[i].0)
                {
                    continue;
                }
                proposals.push(proposal.clone());
                break;
            }
        }
        for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
            env.set_signer(account_id);
            assert!(
                state
                    .vote_new_parameters(state.keyset.epoch_id.next(), &proposals[i])
                    .unwrap()
                    .is_none()
            );
        }

        // Now let's vote for agreeing proposals.
        let proposal = proposals.last().unwrap().clone();

        let original_epoch_id = state.keyset.epoch_id;
        let mut resharing = None;
        // existing participants vote
        let mut n_votes = 0;
        for (account_id, _, _) in participants.participants().iter() {
            if !proposal
                .participants()
                .is_participant_given_account_id(account_id)
            {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        // candidates vote
        for (account_id, _, _) in proposal.participants().participants().iter() {
            if participants.is_participant_given_account_id(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        if num_domains == 0 {
            // If there are no domains, we should transition directly to Running with a higher
            // epoch ID, not resharing.
            assert_eq!(state.keyset.epoch_id, original_epoch_id.next());
            assert_eq!(state.parameters_votes, ThresholdParametersVotes::default());
            assert_eq!(state.add_domains_votes, AddDomainsVotes::default());
        } else {
            let resharing = resharing.unwrap();
            assert_eq!(
                resharing.previous_running_state.parameters,
                state.parameters
            );
            assert_eq!(
                resharing.prospective_epoch_id(),
                state.keyset.epoch_id.next(),
            );
            assert_eq!(
                resharing.resharing_key.proposed_parameters(),
                proposal.parameters()
            );
            assert_eq!(
                resharing.per_domain_thresholds,
                *proposal.per_domain_thresholds()
            );
        }
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(NUM_PROTOCOLS)]
    #[case(2*NUM_PROTOCOLS)]
    fn test_running(#[case] n: usize) {
        test_running_for(n);
    }

    #[rstest]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::Sign)]
    #[case(Protocol::Frost, DomainPurpose::ForeignTx)]
    #[case(Protocol::CaitSith, DomainPurpose::CKD)]
    fn vote_add_domains__should_reject_invalid_protocol_purpose(
        #[case] protocol: Protocol,
        #[case] purpose: DomainPurpose,
    ) {
        // Given
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let next_id = state.domains.next_domain_id();

        let invalid_domain = vec![DomainConfig {
            id: DomainId(next_id),
            protocol,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose,
        }];

        // When
        let err = state.vote_add_domains(invalid_domain).unwrap_err();

        // Then
        assert!(
            err.to_string()
                .contains("Invalid protocol-purpose combination"),
            "Expected InvalidProtocolPurposeCombination, got: {err}"
        );
    }

    fn proposal_with_threshold(state: &RunningContractState, threshold: u64) -> Vec<DomainConfig> {
        let next_id = state.domains.next_domain_id();
        vec![DomainConfig {
            id: DomainId(next_id),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(threshold),
            purpose: DomainPurpose::Sign,
        }]
    }

    #[test]
    fn vote_add_domains__should_reject_threshold_below_two() {
        // Given a running state and a proposal carrying t = 1
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = proposal_with_threshold(&state, 1);

        // When voting to add the domain
        let err = state.vote_add_domains(proposal).unwrap_err();

        // Then the universal lower bound is enforced
        assert!(
            err.to_string()
                .contains("Reconstruction threshold must be at least 2"),
            "Expected ReconstructionThresholdTooLow, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_threshold_exceeding_participants() {
        // Given a running state and a proposal whose threshold > n
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let n = state.parameters.participants().len() as u64;
        let proposal = proposal_with_threshold(&state, n + 1);

        // When voting to add the domain
        let err = state.vote_add_domains(proposal).unwrap_err();

        // Then the upper bound is enforced
        assert!(
            err.to_string().contains("exceeds participant count"),
            "Expected ReconstructionThresholdExceedsParticipants, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_accept_reconstruction_threshold_equal_to_governance() {
        // Given a Frost proposal where the ReconstructionThreshold == the
        // GovernanceThreshold (the new upper boundary case).
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let governance = state.parameters.threshold().value();
        let next_id = state.domains.next_domain_id();
        let proposal = vec![DomainConfig {
            id: DomainId(next_id),
            protocol: Protocol::Frost,
            reconstruction_threshold: ReconstructionThreshold::new(governance),
            purpose: DomainPurpose::Sign,
        }];

        // When voting to add the domain — vote is recorded without error
        let res = state.vote_add_domains(proposal);

        // Then the call succeeds (single voter is below quorum, so no transition)
        assert!(
            res.is_ok(),
            "Expected success at boundary ReconstructionThreshold == GovernanceThreshold: {res:?}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_reconstruction_threshold_above_governance() {
        // Given a Frost proposal whose ReconstructionThreshold exceeds the
        // GovernanceThreshold (but is still <= participant count).
        // GovernanceThreshold 4 < participant count 5, so `governance + 1 <= n`:
        // the rejection comes from the threshold relation, not the n ceiling.
        let mut state = gen_running_state_with_params(1, 5, 4);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let governance = state.parameters.threshold().value();
        let next_id = state.domains.next_domain_id();
        let proposal = vec![DomainConfig {
            id: DomainId(next_id),
            protocol: Protocol::Frost,
            reconstruction_threshold: ReconstructionThreshold::new(governance + 1),
            purpose: DomainPurpose::Sign,
        }];

        // When
        let err = state.vote_add_domains(proposal).unwrap_err();

        // Then the GovernanceThreshold/ReconstructionThreshold relation is enforced via the
        // canonical validate_governance_against_reconstruction helper.
        assert!(
            matches!(
                err,
                Error::InvalidThreshold(InvalidThreshold::BelowReconstructionThreshold { .. })
            ),
            "Expected BelowReconstructionThreshold, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_damgard_etal_threshold_violating_honest_majority() {
        // Given a running state and a DamgardEtAl proposal with `2t - 1 > n`.
        // gen_threshold_params produces n in [3, 30]; pick t = n so that
        // 2t - 1 > n holds (universally true for n >= 2).
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let n = state.parameters.participants().len() as u64;
        let next_id = state.domains.next_domain_id();
        let proposal = vec![DomainConfig {
            id: DomainId(next_id),
            protocol: Protocol::DamgardEtAl,
            reconstruction_threshold: ReconstructionThreshold::new(n),
            purpose: DomainPurpose::Sign,
        }];

        // When voting to add the domain
        let err = state.vote_add_domains(proposal).unwrap_err();

        // Then the DamgardEtAl-specific bound is enforced
        assert!(
            err.to_string().contains("requires at least"),
            "Expected InsufficientParticipantsForProtocol, got: {err}"
        );
    }

    use std::collections::BTreeMap;

    #[test]
    fn process_new_parameters_proposal__should_accept_empty_per_domain_threshold_updates() {
        // Given a running state where existing thresholds are valid under the
        // proposed participant count
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        let proposal = gen_valid_params_proposal(&state.parameters);
        // Sign as a participant present in BOTH the current and proposed sets:
        // `gen_valid_params_proposal` keeps only a random subset of the current
        // participants, so an arbitrary current participant may be absent from
        // the proposal (rejected as a non-participant) and a freshly added one
        // would be deferred as a pending newcomer. The retained overlap is
        // non-empty (at least `threshold` current participants are kept).
        let signer = proposal
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .find(|account_id| {
                state
                    .parameters
                    .participants()
                    .is_participant_given_account_id(account_id)
            })
            .expect("proposal must retain at least one current participant");
        env.set_signer(&signer);

        // When voting with an empty per_domain_thresholds map (legacy shape)
        let res = state.vote_new_parameters(state.keyset.epoch_id.next(), &proposal);

        // Then the vote is recorded without error
        assert!(
            res.is_ok(),
            "Expected accept with empty threshold updates: {res:?}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_reject_threshold_update_with_unknown_domain_id() {
        // Given a running state with one domain
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When voting with a threshold update referencing a non-existent domain ID
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(DomainId(9999), ReconstructionThreshold::new(2));
        let proposal = proposal.with_per_domain_thresholds(threshold_updates);
        let err = state
            .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
            .unwrap_err();

        // Then the unknown-domain guard rejects it
        assert!(
            err.to_string().contains("not in the current registry"),
            "Expected UnknownDomainInProposal, got: {err}"
        );
    }

    /// Builds a `DomainConfig` for the next domain id with the given protocol,
    /// purpose, and reconstruction threshold.
    fn single_domain_proposal(
        state: &RunningContractState,
        protocol: Protocol,
        purpose: DomainPurpose,
        threshold: u64,
    ) -> Vec<DomainConfig> {
        vec![DomainConfig {
            id: DomainId(state.domains.next_domain_id()),
            protocol,
            reconstruction_threshold: ReconstructionThreshold::new(threshold),
            purpose,
        }]
    }

    #[test]
    fn vote_add_domains__should_accept_caitsith_threshold_differing_from_existing() {
        // Given a Running state already holding a CaitSith domain at t = 2
        // (the fixture default) and a proposal for a second CaitSith at t = 3.
        // GovernanceThreshold 5 so a reconstruction threshold of 3 is allowed.
        let mut state = gen_running_state_with_params(1, 5, 5);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = single_domain_proposal(&state, Protocol::CaitSith, DomainPurpose::Sign, 3);

        // When
        let res = state.vote_add_domains(proposal);

        // Then CaitSith domains may carry independent thresholds.
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn vote_add_domains__should_accept_first_caitsith_at_any_valid_threshold() {
        // Given a Running state with no CaitSith domain.
        let mut state = gen_running_state(0);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        // Use the GovernanceThreshold as the ReconstructionThreshold (the maximum allowed).
        let governance = state.parameters.threshold().value();
        let proposal =
            single_domain_proposal(&state, Protocol::CaitSith, DomainPurpose::Sign, governance);

        // When
        let res = state.vote_add_domains(proposal);

        // Then
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn vote_add_domains__should_accept_two_new_caitsith_with_differing_thresholds() {
        // Given a Running state with no existing CaitSith and a proposal
        // adding two CaitSith domains at different thresholds.
        // GovernanceThreshold 5 so reconstruction thresholds 2 and 3 are allowed.
        let mut state = gen_running_state_with_params(0, 5, 5);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let next_id = state.domains.next_domain_id();
        let proposal = vec![
            DomainConfig {
                id: DomainId(next_id),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(next_id + 1),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
        ];

        // When
        let res = state.vote_add_domains(proposal);

        // Then
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn process_new_parameters_proposal__should_apply_threshold_update_to_validation() {
        // Given a running state with one domain whose existing threshold would
        // remain valid under the new participants, but the threshold update
        // swaps it for an invalid (too-low) value.
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When voting with a threshold update that violates the universal lower bound
        let domain_id = state.domains.domains()[0].id;
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(domain_id, ReconstructionThreshold::new(1));
        let proposal = proposal.with_per_domain_thresholds(threshold_updates);
        let err = state
            .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
            .unwrap_err();

        // Then the updated value (not the stored value) is validated and rejected
        assert!(
            err.to_string()
                .contains("Reconstruction threshold must be at least"),
            "Expected ReconstructionThresholdTooLow on updated value, got: {err}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_accept_valid_per_domain_threshold_update() {
        // Given a running state with one CaitSith domain at the fixture default
        // t = 2.
        // GovernanceThreshold 4 so the proposal's ReconstructionThreshold (3) fits.
        let mut state = gen_running_state_with_params(1, 5, 4);
        let mut env = Environment::new(None, None, None);
        let proposal = gen_valid_params_proposal(&state.parameters);
        // Sign as a participant present in BOTH the current and proposed sets
        // (see the empty-updates test for why an arbitrary participant won't do).
        let signer = proposal
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .find(|account_id| {
                state
                    .parameters
                    .participants()
                    .is_participant_given_account_id(account_id)
            })
            .expect("proposal must retain at least one current participant");
        env.set_signer(&signer);

        // When voting with an update raising t to 3, which stays within both the proposed
        // participant count and the GovernanceThreshold (>= 3 by the pinned params above).
        let domain_id = state.domains.domains()[0].id;
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(domain_id, ReconstructionThreshold::new(3));
        let proposal = proposal.with_per_domain_thresholds(threshold_updates);
        let res = state.vote_new_parameters(state.keyset.epoch_id.next(), &proposal);

        // Then the vote is recorded without error
        assert!(
            res.is_ok(),
            "Expected accept with valid threshold update: {res:?}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_reject_threshold_update_exceeding_participant_count()
    {
        // Given a running state with one domain
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When the update sets t above the proposed participant count
        let domain_id = state.domains.domains()[0].id;
        let new_num_participants = proposal.participants().len() as u64;
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(
            domain_id,
            ReconstructionThreshold::new(new_num_participants + 1),
        );
        let proposal = proposal.with_per_domain_thresholds(threshold_updates);
        let err = state
            .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
            .unwrap_err();

        // Then the updated value is validated against the proposed participants
        // and rejected.
        assert!(
            err.to_string().contains("exceeds participant count"),
            "Expected ReconstructionThresholdExceedsParticipants, got: {err}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_accept_threshold_update_diverging_caitsith() {
        // Given a running state with two CaitSith domains, both at the fixture
        // default t = 2 (the protocols cycle, so 5 domains yields two CaitSith).
        // GovernanceThreshold 4 so the proposal's ReconstructionThreshold (3) fits.
        let mut state = gen_running_state_with_params(5, 5, 4);
        let mut env = Environment::new(None, None, None);
        assert!(
            state
                .domains
                .domains()
                .iter()
                .filter(|d| d.protocol == Protocol::CaitSith)
                .count()
                >= 2,
            "fixture must contain at least two CaitSith domains"
        );
        let proposal = gen_valid_params_proposal(&state.parameters);
        // Sign as a participant present in BOTH the current and proposed sets
        // (the proposal keeps a random subset of current participants).
        let signer = proposal
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .find(|account_id| {
                state
                    .parameters
                    .participants()
                    .is_participant_given_account_id(account_id)
            })
            .expect("proposal must retain at least one current participant");
        env.set_signer(&signer);

        // When an update raises only one CaitSith domain's threshold, leaving the
        // CaitSith domains non-uniform.
        let caitsith_id = state
            .domains
            .domains()
            .iter()
            .find(|d| d.protocol == Protocol::CaitSith)
            .map(|d| d.id)
            .expect("fixture has a CaitSith domain");
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(caitsith_id, ReconstructionThreshold::new(3));
        let proposal = proposal.with_per_domain_thresholds(threshold_updates);
        let res = state.vote_new_parameters(state.keyset.epoch_id.next(), &proposal);

        // Then CaitSith domains may diverge in threshold.
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn vote_add_domains__should_accept_caitsith_threshold_matching_existing() {
        // Given a Running state with a CaitSith domain at t = 2 (fixture
        // default) and a matching proposal.
        let mut state = gen_running_state(1);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = single_domain_proposal(&state, Protocol::CaitSith, DomainPurpose::Sign, 2);

        // When
        let res = state.vote_add_domains(proposal);

        // Then
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn vote_add_domains__should_accept_non_caitsith_domain_with_differing_threshold() {
        // Given a Running state with a CaitSith domain at t = 2 and a Frost
        // proposal at a different threshold.
        let mut state = gen_running_state_with_params(1, 4, 3);
        let mut env = Environment::new(None, None, None);
        env.set_signer(&state.parameters.participants().participants()[0].0);
        let proposal = single_domain_proposal(&state, Protocol::Frost, DomainPurpose::Sign, 3);

        // When
        let res = state.vote_add_domains(proposal);

        // Then
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }
}
