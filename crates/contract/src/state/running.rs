use super::initializing::InitializingContractState;
use super::key_event::KeyEvent;
use super::resharing::ResharingContractState;
use crate::errors::{DomainError, Error, InvalidParameters, InvalidState};
use crate::primitives::participants::{IdentifiesParticipant, ParticipantInfo, Participants};
use crate::primitives::{
    domain::{
        AddDomainsVotes, DomainRegistry, validate_domain_purpose,
        validate_domains_against_governance,
    },
    key_state::{AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, Keyset},
    threshold_votes::GovernanceThresholdParametersVotes,
    thresholds::{GovernanceThresholdParameters, ProposedGovernanceThresholdParameters},
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{DomainConfig, DomainId, ReconstructionThreshold};
use near_sdk::near;
use std::collections::{BTreeMap, BTreeSet};

/// In this state, the contract is ready to process signature requests.
///
/// Proposals can be submitted to modify the state:
///  - vote_add_domains, upon threshold agreement, transitions into the
///    Initializing state to generate keys for new domains.
///  - vote_new_parameters, upon governance threshold agreement, transitions into the
///    Resharing state to reshare keys for new participants and also change the
///    threshold if desired.
///  - trigger_key_refresh, once a key refresh is due, transitions into the Resharing
///    state to reshare keys for the same participants and thresholds.
#[near(serializers=[borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningContractState {
    /// The domains for which we have a key ready for signature processing.
    pub domains: DomainRegistry,
    /// The keys that are currently in use; for each domain provides an unique identifier for a
    /// distributed key, so that the nodes can identify which local keyshare to use.
    pub keyset: Keyset,
    /// The current participants and threshold.
    pub parameters: GovernanceThresholdParameters,
    /// The previous epoch id for a resharing state that was cancelled.
    /// This epoch id is tracked, as the next time the state transitions to resharing,
    /// we can't reuse a previously cancelled epoch id.
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl RunningContractState {
    pub fn new(
        domains: DomainRegistry,
        keyset: Keyset,
        parameters: GovernanceThresholdParameters,
    ) -> Self {
        RunningContractState {
            domains,
            keyset,
            parameters,
            previously_cancelled_resharing_epoch_id: None,
        }
    }

    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContractState if the proposal is accepted.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: &ProposedGovernanceThresholdParameters,
        votes: &mut GovernanceThresholdParametersVotes,
    ) -> Result<Option<ResharingContractState>, Error> {
        let expected_prospective_epoch_id = self.prospective_epoch_id();

        if prospective_epoch_id != expected_prospective_epoch_id {
            return Err(InvalidParameters::EpochMismatch {
                expected: expected_prospective_epoch_id,
                provided: prospective_epoch_id,
            }
            .into());
        }

        if !self.process_new_parameters_proposal(proposal, votes)? {
            return Ok(None);
        }
        let resharing = self.resharing_onto(
            proposal.parameters().clone(),
            proposal.per_domain_thresholds().clone(),
        );
        if resharing.is_none() {
            // New parameters were proposed, but we have no keys, so directly
            // transition into Running state but bump the EpochId. With no
            // domains the per-domain threshold updates have nothing to apply to
            // and are dropped.
            *self = RunningContractState::new(
                self.domains.clone(),
                Keyset::new(self.keyset.epoch_id.next(), Vec::new()),
                proposal.parameters().clone(),
            );
        }
        Ok(resharing)
    }

    /// Returns the state that reshares every key onto the current participants and thresholds.
    /// Fails if the signer is not a participant or there are no keys.
    pub fn key_refresh(&self) -> Result<ResharingContractState, Error> {
        AuthenticatedAccountId::new(self.parameters.participants())?;
        self.resharing_onto(self.parameters.clone(), BTreeMap::new())
            .ok_or_else(|| InvalidState::NoKeysToRefresh.into())
    }

    fn resharing_onto(
        &self,
        parameters: GovernanceThresholdParameters,
        per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
    ) -> Option<ResharingContractState> {
        let first_domain = self.domains.get_domain_by_index(0)?;
        Some(ResharingContractState {
            previous_running_state: RunningContractState::new(
                self.domains.clone(),
                self.keyset.clone(),
                self.parameters.clone(),
            ),
            reshared_keys: Vec::new(),
            resharing_key: KeyEvent::new(
                self.prospective_epoch_id(),
                first_domain.clone(),
                parameters,
            ),
            cancellation_requests: BTreeSet::new(),
            per_domain_thresholds,
        })
    }

    pub fn participants(&self) -> &Participants {
        self.parameters.participants()
    }

    pub fn keyset(&self) -> &Keyset {
        &self.keyset
    }

    pub fn update_participant_info(
        &mut self,
        account_id: AccountId,
        new_info: ParticipantInfo,
    ) -> Result<(), Error> {
        self.parameters.update_info(account_id, new_info)
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

    /// Casts a vote for `proposal`, removing any previous votes by [`env::signer_account_id()`](near_sdk::env::signer_account_id).
    /// Fails if the proposal is invalid or the signer is not a current participant.
    /// Returns true once the current participants' governance threshold voted for it; pending
    /// votes are then cleared.
    pub(super) fn process_new_parameters_proposal(
        &self,
        proposal: &ProposedGovernanceThresholdParameters,
        votes: &mut GovernanceThresholdParametersVotes,
    ) -> Result<bool, Error> {
        // ensure the proposal is valid against the current parameters
        self.parameters
            .validate_incoming_proposal(proposal.parameters())?;

        // Validate effective per-domain thresholds (updates override, absent
        // domains keep theirs) against the proposed participant count.
        let new_num_participants = proposal.participants().count();
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

        // The GovernanceThreshold must dominate every domain's effective ReconstructionThreshold;
        // enforced here so the state transition is self-contained (single source of truth).
        validate_domains_against_governance(
            &effective_domains,
            new_num_participants,
            proposal.threshold(),
        )?;

        // As in every other governance vote, the current participants decide: accounts the
        // proposal would add have no vote, and those it would remove keep theirs.
        let voter = AuthenticatedAccountId::new(self.parameters.participants())?;

        // finally, vote.
        let accepted = votes.vote(proposal, voter, &self.parameters);
        if accepted {
            votes.clear();
        }
        Ok(accepted)
    }

    /// Casts a vote for the signer participant to add new domains, replacing any previous vote.
    /// Once every participant voted for the same set of new domains, returns the
    /// InitializingContractState we should transition into to generate keys for these new
    /// domains; pending votes are then cleared.
    pub fn vote_add_domains(
        &self,
        domains: Vec<DomainConfig>,
        votes: &mut AddDomainsVotes,
    ) -> Result<Option<InitializingContractState>, Error> {
        if domains.is_empty() {
            return Err(DomainError::AddDomainsMustAddAtLeastOneDomain.into());
        }
        let num_participants = self.parameters.participants().count();
        for domain in &domains {
            validate_domain_purpose(domain)?;
        }
        // Keep trust assumptions consistent: a domain must never require more shares to
        // reconstruct than the GovernanceThreshold demands to govern. Route through the
        // canonical helper so the cross-domain invariant has a single source of truth.
        validate_domains_against_governance(
            &domains,
            num_participants,
            self.parameters.threshold(),
        )?;
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;
        if votes.vote(&domains, participant, self.parameters.participants()) {
            votes.clear();
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

    pub fn is_participant<K: IdentifiesParticipant>(&self, id: &K) -> bool {
        self.parameters.participants().is_participant(id)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
pub mod running_tests {
    use std::collections::BTreeMap;

    use rstest::rstest;

    use super::RunningContractState;
    use crate::errors::{Error, InvalidState, InvalidThreshold};
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::test_utils::{NUM_PROTOCOLS, gen_proposed_threshold_params};
    use crate::primitives::threshold_votes::GovernanceThresholdParametersVotes;
    use crate::primitives::thresholds::{
        GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
    };
    use crate::state::key_event::tests::Environment;
    use crate::state::test_utils::{
        RunningStateParams, account_ids, gen_running_state, gen_running_state_with_params,
        gen_valid_params_proposal, threshold_voters,
    };
    use near_mpc_contract_interface::types::{
        DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
    };
    use near_sdk::AccountId;
    use std::assert_matches;

    struct SetupOpts {
        num_participants: usize,
        governance_threshold: GovernanceThreshold,
    }

    fn setup(num_domains: usize, opts: Option<SetupOpts>) -> RunningContractState {
        let state = match opts {
            Some(opts) => gen_running_state_with_params(RunningStateParams {
                num_domains,
                num_participants: opts.num_participants,
                governance_threshold: opts.governance_threshold,
            }),
            None => gen_running_state(num_domains),
        };
        let first_participant = state.parameters.participants().participants()[0].0.clone();
        Environment::new(None, Some(first_participant), None);
        state
    }

    /// Builds a one-domain proposal for the next domain id.
    fn single_domain_proposal(
        state: &RunningContractState,
        protocol: Protocol,
        purpose: DomainPurpose,
        reconstruction_threshold: ReconstructionThreshold,
    ) -> Vec<DomainConfig> {
        vec![DomainConfig {
            id: state.domains.next_domain_id(),
            protocol,
            reconstruction_threshold,
            purpose,
        }]
    }

    fn test_running_for(num_domains: usize) {
        let mut state = gen_running_state(num_domains);
        println!(
            "Participants: {}, threshold: {}",
            state.parameters.participants().count(),
            state.parameters.threshold().value()
        );
        let mut env = Environment::new(None, None, None);
        let mut votes = GovernanceThresholdParametersVotes::default();
        let participants = state.parameters.participants().clone();
        // Assert that random proposals get rejected.
        for (account_id, _, _) in participants.participants() {
            let ksp = gen_proposed_threshold_params(30);
            env.set_signer(account_id);
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &ksp, &mut votes)
                .unwrap_err();
        }
        // Assert that proposals of the wrong epoch ID get rejected.
        {
            let ksp = gen_valid_params_proposal(&state.parameters);
            env.set_signer(&participants.participants()[0].0);
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id, &ksp, &mut votes)
                .unwrap_err();
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id.next().next(), &ksp, &mut votes)
                .unwrap_err();
        }
        // Assert that disagreeing proposals do not reach consensus.
        // Generate an extra proposal for the next step.
        let mut proposals = Vec::new();
        while proposals.len() < participants.participants().len() + 1 {
            let proposal = gen_valid_params_proposal(&state.parameters);
            if !proposals.contains(&proposal) {
                proposals.push(proposal);
            }
        }
        for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
            env.set_signer(account_id);
            assert!(
                state
                    .vote_new_parameters(state.keyset.epoch_id.next(), &proposals[i], &mut votes)
                    .unwrap()
                    .is_none()
            );
        }

        // Now let's vote for agreeing proposals.
        let proposal = proposals.last().unwrap().clone();

        let original_epoch_id = state.keyset.epoch_id;
        let has_domains = !state.domains.domains().is_empty();
        let mut resharing = None;
        // existing participants vote until their governance threshold is met
        let voters = threshold_voters(&state.parameters);
        for account_id in &voters {
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal, &mut votes)
                .unwrap();
            if Some(account_id) != voters.last() || !has_domains {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        if !has_domains {
            // If there are no domains, we should transition directly to Running with a higher
            // epoch ID, not resharing.
            assert_eq!(state.keyset.epoch_id, original_epoch_id.next());
            assert!(votes.is_empty());
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
        let state = setup(1, None);
        let invalid_domain =
            single_domain_proposal(&state, protocol, purpose, ReconstructionThreshold::new(2));

        // When
        let err = state
            .vote_add_domains(invalid_domain, &mut AddDomainsVotes::default())
            .unwrap_err();

        // Then
        assert!(
            err.to_string()
                .contains("Invalid protocol-purpose combination"),
            "Expected InvalidProtocolPurposeCombination, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_threshold_below_two() {
        // Given
        let state = setup(1, None);
        let proposal = single_domain_proposal(
            &state,
            Protocol::CaitSith,
            DomainPurpose::Sign,
            ReconstructionThreshold::new(1),
        );

        // When
        let err = state
            .vote_add_domains(proposal, &mut AddDomainsVotes::default())
            .unwrap_err();

        // Then
        assert!(
            err.to_string()
                .contains("Reconstruction threshold must be at least 2"),
            "Expected ReconstructionThresholdTooLow, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_threshold_exceeding_participants() {
        // Given
        let state = setup(1, None);
        let n = state.parameters.participants().count().value();
        let proposal = single_domain_proposal(
            &state,
            Protocol::CaitSith,
            DomainPurpose::Sign,
            ReconstructionThreshold::new(n + 1),
        );

        // When
        let err = state
            .vote_add_domains(proposal, &mut AddDomainsVotes::default())
            .unwrap_err();

        // Then
        assert!(
            err.to_string().contains("exceeds participant count"),
            "Expected ReconstructionThresholdExceedsParticipants, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_reconstruction_threshold_above_governance() {
        // Given governance 4 < n = 5, so `governance + 1 <= n`: the rejection
        // comes from the threshold relation, not the n ceiling.
        let state = setup(
            1,
            Some(SetupOpts {
                num_participants: 5,
                governance_threshold: GovernanceThreshold::new(4),
            }),
        );
        let governance = state.parameters.threshold().value();
        let proposal = single_domain_proposal(
            &state,
            Protocol::Frost,
            DomainPurpose::Sign,
            ReconstructionThreshold::new(governance + 1),
        );

        // When
        let err = state
            .vote_add_domains(proposal, &mut AddDomainsVotes::default())
            .unwrap_err();

        // Then
        assert!(
            matches!(
                err,
                Error::InvalidThreshold(InvalidThreshold::BelowReconstructionThreshold { .. })
            ),
            "Expected BelowReconstructionThreshold, got: {err}"
        );
    }

    #[test]
    fn vote_add_domains__should_reject_robust_ecdsa_threshold_violating_honest_majority() {
        // Given a RobustEcdsa proposal with t = n, so `2t - 1 > n` for any n >= 2.
        let state = setup(1, None);
        let n = state.parameters.participants().count().value();
        let proposal = single_domain_proposal(
            &state,
            Protocol::RobustEcdsa,
            DomainPurpose::Sign,
            ReconstructionThreshold::new(n),
        );

        // When
        let err = state
            .vote_add_domains(proposal, &mut AddDomainsVotes::default())
            .unwrap_err();

        // Then
        assert!(
            err.to_string().contains("requires at least"),
            "Expected InsufficientParticipantsForProtocol, got: {err}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_accept_empty_per_domain_threshold_updates() {
        // Given
        let mut state = setup(1, None);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When voting with an empty per_domain_thresholds map (legacy shape)
        let res = state.vote_new_parameters(
            state.keyset.epoch_id.next(),
            &proposal,
            &mut GovernanceThresholdParametersVotes::default(),
        );

        // Then
        assert!(
            res.is_ok(),
            "Expected accept with empty threshold updates: {res:?}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_reject_threshold_update_with_unknown_domain_id() {
        // Given
        let mut state = setup(1, None);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When voting with a threshold update for a non-existent domain ID
        let proposal = proposal.with_per_domain_thresholds(BTreeMap::from([(
            DomainId(9999),
            ReconstructionThreshold::new(2),
        )]));
        let err = state
            .vote_new_parameters(
                state.keyset.epoch_id.next(),
                &proposal,
                &mut GovernanceThresholdParametersVotes::default(),
            )
            .unwrap_err();

        // Then
        assert!(
            err.to_string().contains("not in the current registry"),
            "Expected UnknownDomainInProposal, got: {err}"
        );
    }

    struct ParticipantsUpdate {
        state: RunningContractState,
        proposal: ProposedGovernanceThresholdParameters,
        retained: Vec<AccountId>,
        removed: Vec<AccountId>,
        added: Vec<AccountId>,
    }

    const NUM_PARTICIPANTS: usize = 5;
    const GOVERNANCE_THRESHOLD: u64 = 3;
    const NUM_REPLACED: usize = 2;
    const NUM_RETAINED: usize = NUM_PARTICIPANTS - NUM_REPLACED;

    /// Proposal that replaces the last current participants with added ones.
    fn gen_participants_update() -> ParticipantsUpdate {
        let state = gen_running_state_with_params(RunningStateParams {
            num_domains: 1,
            num_participants: NUM_PARTICIPANTS,
            governance_threshold: GovernanceThreshold::new(GOVERNANCE_THRESHOLD),
        });
        let mut proposed = state.parameters.participants().subset(0..NUM_RETAINED);
        proposed.add_random_participants_till_n(NUM_PARTICIPANTS);

        let mut retained = account_ids(state.parameters.participants());
        let removed = retained.split_off(NUM_RETAINED);
        let added = account_ids(&proposed).split_off(NUM_RETAINED);
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(proposed, state.parameters.threshold()).unwrap(),
            BTreeMap::new(),
        );
        ParticipantsUpdate {
            state,
            proposal,
            retained,
            removed,
            added,
        }
    }

    #[test]
    fn process_new_parameters_proposal__should_reject_votes_from_added_participants() {
        // Given
        let ParticipantsUpdate {
            state,
            proposal,
            added,
            ..
        } = gen_participants_update();
        let mut env = Environment::new(None, None, None);
        let mut votes = GovernanceThresholdParametersVotes::default();

        for voter in &added {
            env.set_signer(voter);

            // When
            let result = state.process_new_parameters_proposal(&proposal, &mut votes);

            // Then
            assert_matches!(
                result.unwrap_err(),
                Error::InvalidState(InvalidState::NotParticipant { account_id }) if account_id == *voter
            );
        }
        assert!(votes.is_empty());
    }

    const NO_REMOVED_VOTERS: usize = 0;

    #[rstest]
    #[case::retained_participants_only(NO_REMOVED_VOTERS)]
    #[case::removed_participants_first(NUM_REPLACED)]
    fn process_new_parameters_proposal__should_return_true_once_threshold_current_participants_voted(
        #[case] num_removed_voters: usize,
    ) {
        // Given
        let ParticipantsUpdate {
            state,
            proposal,
            retained,
            removed,
            ..
        } = gen_participants_update();
        let voters: Vec<AccountId> = removed
            .into_iter()
            .take(num_removed_voters)
            .chain(retained)
            .take(usize::try_from(state.parameters.threshold().value()).unwrap())
            .collect();
        let mut env = Environment::new(None, None, None);
        let mut votes = GovernanceThresholdParametersVotes::default();

        // When
        let accepted: Vec<bool> = voters
            .iter()
            .map(|voter| {
                env.set_signer(voter);
                state
                    .process_new_parameters_proposal(&proposal, &mut votes)
                    .unwrap()
            })
            .collect();

        // Then
        assert_eq!(accepted, [false, false, true]);
        assert!(votes.is_empty());
    }

    /// `reconstruction_threshold: None` means the GovernanceThreshold (the
    /// maximum allowed); `pinned_params: None` uses the randomized fixture.
    #[rstest]
    #[case::caitsith_threshold_differing_from_existing(1, Some((5, 5)), Protocol::CaitSith, Some(3))]
    #[case::caitsith_threshold_matching_existing(1, None, Protocol::CaitSith, Some(2))]
    #[case::first_caitsith_at_governance_threshold(0, None, Protocol::CaitSith, None)]
    #[case::reconstruction_threshold_equal_to_governance(1, None, Protocol::Frost, None)]
    #[case::non_caitsith_threshold_differing_from_existing(1, Some((4, 3)), Protocol::Frost, Some(3))]
    fn vote_add_domains__should_accept_valid_domain_proposal(
        #[case] num_domains: usize,
        #[case] pinned_params: Option<(usize, u64)>,
        #[case] protocol: Protocol,
        #[case] reconstruction_threshold: Option<u64>,
    ) {
        // Given
        let opts = pinned_params.map(|(num_participants, governance_threshold)| SetupOpts {
            num_participants,
            governance_threshold: GovernanceThreshold::new(governance_threshold),
        });
        let state = setup(num_domains, opts);
        let reconstruction_threshold = reconstruction_threshold
            .map(ReconstructionThreshold::new)
            .unwrap_or_else(|| ReconstructionThreshold::from(state.parameters.threshold()));
        let proposal = single_domain_proposal(
            &state,
            protocol,
            DomainPurpose::Sign,
            reconstruction_threshold,
        );

        // When
        let res = state.vote_add_domains(proposal, &mut AddDomainsVotes::default());

        // Then the vote is recorded (single voter is below quorum, so no transition)
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn vote_add_domains__should_accept_two_new_caitsith_with_differing_thresholds() {
        // Given a proposal adding two CaitSith domains at different thresholds
        let state = setup(
            0,
            Some(SetupOpts {
                num_participants: 5,
                governance_threshold: GovernanceThreshold::new(5),
            }),
        );
        let next_id = state.domains.next_domain_id();
        let proposal = vec![
            DomainConfig {
                id: next_id,
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(next_id.0 + 1),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
        ];

        // When
        let res = state.vote_add_domains(proposal, &mut AddDomainsVotes::default());

        // Then
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }

    #[test]
    fn process_new_parameters_proposal__should_apply_threshold_update_to_validation() {
        // Given
        let mut state = setup(1, None);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When a threshold update swaps a valid stored value for a too-low one
        let domain_id = state.domains.domains()[0].id;
        let proposal = proposal.with_per_domain_thresholds(BTreeMap::from([(
            domain_id,
            ReconstructionThreshold::new(1),
        )]));
        let err = state
            .vote_new_parameters(
                state.keyset.epoch_id.next(),
                &proposal,
                &mut GovernanceThresholdParametersVotes::default(),
            )
            .unwrap_err();

        // Then the updated value, not the stored one, is validated
        assert!(
            err.to_string()
                .contains("Reconstruction threshold must be at least"),
            "Expected ReconstructionThresholdTooLow on updated value, got: {err}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_accept_valid_per_domain_threshold_update() {
        // Given governance 4 so a ReconstructionThreshold of 3 fits
        let mut state = setup(
            1,
            Some(SetupOpts {
                num_participants: 5,
                governance_threshold: GovernanceThreshold::new(4),
            }),
        );
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When voting with an update raising t from the fixture default 2 to 3
        let domain_id = state.domains.domains()[0].id;
        let proposal = proposal.with_per_domain_thresholds(BTreeMap::from([(
            domain_id,
            ReconstructionThreshold::new(3),
        )]));
        let res = state.vote_new_parameters(
            state.keyset.epoch_id.next(),
            &proposal,
            &mut GovernanceThresholdParametersVotes::default(),
        );

        // Then
        assert!(
            res.is_ok(),
            "Expected accept with valid threshold update: {res:?}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_reject_threshold_update_exceeding_participant_count()
    {
        // Given
        let mut state = setup(1, None);
        let proposal = gen_valid_params_proposal(&state.parameters);

        // When the update sets t above the proposed participant count
        let domain_id = state.domains.domains()[0].id;
        let new_num_participants = proposal.participants().count().value();
        let proposal = proposal.with_per_domain_thresholds(BTreeMap::from([(
            domain_id,
            ReconstructionThreshold::new(new_num_participants + 1),
        )]));
        let err = state
            .vote_new_parameters(
                state.keyset.epoch_id.next(),
                &proposal,
                &mut GovernanceThresholdParametersVotes::default(),
            )
            .unwrap_err();

        // Then the updated value is validated against the proposed participants
        assert!(
            err.to_string().contains("exceeds participant count"),
            "Expected ReconstructionThresholdExceedsParticipants, got: {err}"
        );
    }

    #[test]
    fn process_new_parameters_proposal__should_accept_threshold_update_diverging_caitsith() {
        // Given two CaitSith domains at the fixture default t = 2 (the
        // protocols cycle, so 5 domains yields two CaitSith)
        let mut state = setup(
            5,
            Some(SetupOpts {
                num_participants: 5,
                governance_threshold: GovernanceThreshold::new(4),
            }),
        );
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

        // When an update raises only one CaitSith domain's threshold
        let caitsith_id = state
            .domains
            .domains()
            .iter()
            .find(|d| d.protocol == Protocol::CaitSith)
            .map(|d| d.id)
            .expect("fixture has a CaitSith domain");
        let proposal = proposal.with_per_domain_thresholds(BTreeMap::from([(
            caitsith_id,
            ReconstructionThreshold::new(3),
        )]));
        let res = state.vote_new_parameters(
            state.keyset.epoch_id.next(),
            &proposal,
            &mut GovernanceThresholdParametersVotes::default(),
        );

        // Then CaitSith domains may diverge in threshold.
        assert!(res.is_ok(), "Expected acceptance: {res:?}");
    }
}
