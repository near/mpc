//! Governance votes over the participant set and the domain registry.

use crate::dto_mapping::{IntoInterfaceType, TryIntoContractType};
use crate::errors::{Error, InvalidParameters};
use crate::primitives::thresholds::{GovernanceThreshold, ProposedGovernanceThresholdParameters};
use crate::tee::tee_state::TeeValidationResult;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{env, log, near};
use std::time::Duration;

#[near]
impl MpcContract {
    #[expect(rustdoc::private_intra_doc_links)]
    /// Propose new parameters for the MPC network: participants, governance
    /// threshold, and optional per-domain
    /// [`ReconstructionThreshold`](near_mpc_contract_interface::types::ReconstructionThreshold) updates
    /// (empty map keeps the current ones), applied on resharing completion.
    /// If a threshold number of votes are reached on the exact same proposal, this will transition
    /// the contract into the Resharing state.
    ///
    /// The epoch_id must be equal to 1 plus the current epoch ID (if Running) or prospective epoch
    /// ID (if Resharing). Otherwise the vote is ignored. This is to prevent late transactions from
    /// accidentally voting on outdated proposals.
    ///
    /// Like the other governance voting methods, this must be called directly from the
    /// participant's own NEAR account: [`assert_caller_is_signer()`](MpcContract::assert_caller_is_signer) requires
    /// `signer_account_id == predecessor_account_id`, so calls forwarded through another
    /// contract are rejected.
    #[handle_result]
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: dtos::EpochId,
        proposal: dtos::ProposedGovernanceThresholdParameters,
    ) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        let proposal: ProposedGovernanceThresholdParameters = proposal.try_into_contract_type()?;
        log!(
            "vote_new_parameters: signer={}, proposal={:?}",
            env::signer_account_id(),
            proposal,
        );

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        let validation_result = self.tee_state.reverify_and_cleanup_participants(
            proposal.participants(),
            tee_upgrade_deadline_duration,
        );

        let proposed_participants = proposal.participants();
        match validation_result {
            TeeValidationResult::Full => {
                if let Some(new_state) = self.protocol_state.vote_new_parameters(
                    prospective_epoch_id,
                    &proposal,
                    &mut self.parameters_votes,
                )? {
                    self.protocol_state = new_state;
                }
                Ok(())
            }
            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            } => {
                let invalid_participants: Vec<_> = proposed_participants
                    .participants()
                    .iter()
                    .filter(|(account_id, _, _)| {
                        !participants_with_valid_attestation.is_participant(account_id)
                    })
                    .collect();

                Err(InvalidParameters::InvalidTeeRemoteAttestation {
                    reason: format!(
                        "The following participants have invalid TEE status: {:?}",
                        invalid_participants
                    ),
                }
                .into())
            }
        }
    }

    /// Propose adding a new set of domains for the MPC network.
    /// If a threshold number of votes are reached on the exact same proposal, this will transition
    /// the contract into the Initializing state to generate keys for the new domains.
    ///
    /// The specified list of domains must have increasing and contiguous IDs, and the first ID
    /// must be the same as the `next_domain_id` returned by state().
    #[handle_result]
    pub fn vote_add_domains(&mut self, domains: Vec<dtos::DomainConfig>) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        log!(
            "vote_add_domains: signer={}, domains={:?}",
            env::signer_account_id(),
            domains,
        );

        if let Some(new_state) = self.protocol_state.vote_add_domains(domains)? {
            self.protocol_state = new_state;
            self.parameters_votes.clear();
        }
        Ok(())
    }

    /// Returns the pending `vote_new_parameters` votes, keyed by proposal hash.
    pub fn parameters_votes(&self) -> dtos::GovernanceThresholdParametersVotes {
        (&self.parameters_votes).into_dto_type()
    }
}

impl MpcContract {
    pub(crate) fn threshold(&self) -> Result<GovernanceThreshold, Error> {
        self.protocol_state.threshold()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{
        FORWARDER_ACCOUNT_ID, init_running_with_domain, must_get_attested_signer_key,
        prepay_and_attest_all_participants, resharing_state,
        running_contract_called_by_participant_via_forwarder, running_state,
        setup_tee_test_contract, submit_attestation, submit_valid_attestations,
    };
    use crate::errors::{DomainError, InvalidCandidateSet, InvalidState, InvalidThreshold};
    use crate::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use crate::primitives::participants::Participants;
    use crate::primitives::proposal_hash::ToProposalHash;
    use crate::primitives::test_utils::{authenticate_account_as, gen_participants};
    use crate::primitives::thresholds::GovernanceThresholdParameters;
    use crate::state::ProtocolContractState;
    use crate::state::key_event::tests::find_leader;
    use crate::tee::tee_state::TeeState;
    use crate::tee::test_utils::Environment;
    use dtos::{DomainId, ParticipantCount, Protocol, ReconstructionThreshold};
    use near_mpc_contract_interface::types::DomainPurpose;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, NearToken, testing_env};
    use rstest::rstest;
    use std::{assert_matches, collections::BTreeMap};

    /// Sets up the voting context and calls [`MpcContract::vote_new_parameters`] with the
    /// given parameters.
    fn setup_voting_context_and_vote(
        contract: &mut MpcContract,
        first_participant_id: &AccountId,
        participants: Participants,
        governance_threshold: GovernanceThreshold,
    ) -> Result<(), Error> {
        let voting_context = VMContextBuilder::new()
            .signer_account_id(first_participant_id.clone())
            .predecessor_account_id(first_participant_id.clone())
            .attached_deposit(NearToken::ZERO)
            .build();
        testing_env!(voting_context);

        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, governance_threshold).unwrap(),
            BTreeMap::new(),
        );
        contract.vote_new_parameters(dtos::EpochId::new(1), (&proposal).into_dto_type())
    }

    /// Test that [`MpcContract::vote_new_parameters`] succeeds when all participants
    /// submit valid TEE attestations. This tests the scenario where all participants successfully
    /// submit valid attestations through [`MpcContract::submit_participant_info`],
    /// resulting in a valid TEE status for all participants.
    #[test]
    fn test_vote_new_parameters_succeeds_when_all_participants_have_valid_tee() {
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(3, 2);
        let governance_threshold = GovernanceThreshold::new(2);

        // Submit valid attestations for all participants
        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        // This should succeed because all participants now have valid TEE status
        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            governance_threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when all participants have valid TEE status"
        );
    }

    /// Test that attempts to submit invalid attestations are rejected by
    /// [`MpcContract::submit_participant_info`]. This test demonstrates that
    /// participants cannot have Invalid TEE status because the contract proactively rejects
    /// invalid attestations at submission time. The 4th participant tries to submit an invalid
    /// attestation but is rejected, keeping the attestation it submitted right after
    /// initialization, which combined with valid participants still allows successful voting.
    #[test]
    fn test_vote_new_parameters_succeeds_after_invalid_attestation_rejected() {
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(4, 3);
        let governance_threshold = GovernanceThreshold::new(3);

        // Submit valid attestations for first 3 participants
        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        // Try to submit invalid attestation for the 4th participant
        let participant_index = 3;
        let result = submit_attestation(&mut contract, &participants, participant_index, false);
        assert!(
            result.is_err(),
            "Invalid attestation should be rejected by submit_participant_info"
        );

        if let Err(error) = result {
            let error_string = error.to_string();
            assert!(
                error_string.contains("failed verification"),
                "Error should mention attestation verification failure, got: {}",
                error_string
            );
        }

        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            governance_threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when the rejected submission leaves the initial attestation in place"
        );
    }

    #[rstest]
    fn vote_new_parameters__should_reject_a_participant_without_its_own_node(
        #[values(running_state(), resharing_state())] protocol_state: ProtocolContractState,
    ) {
        // Given
        let mut contract = MpcContract::new_from_protocol_state(protocol_state);
        let parameters = contract
            .protocol_state
            .threshold_parameters_or_panic()
            .clone();
        contract.tee_state =
            TeeState::with_mocked_participant_attestations(parameters.participants());
        let mut participants = parameters.participants().clone();
        participants.add_random_participants_till_n(participants.len() + 1);
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, parameters.threshold()).unwrap(),
            BTreeMap::new(),
        );
        let voter = parameters.participants().participants()[0].0.clone();
        let state_before = contract.state();

        // When
        let result = vote_params(&mut contract, &voter, &proposal);

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(
                InvalidParameters::InvalidTeeRemoteAttestation { .. }
            ))
        );
        assert_eq!(contract.state(), state_before);
    }

    /// Builds a Running contract with `num_participants` participants, the given
    /// governance threshold, and a single CaitSith [`Sign`] domain with the given
    /// reconstruction threshold.
    fn setup_running_contract_with_domain(
        num_participants: usize,
        governance_threshold: GovernanceThreshold,
        reconstruction_threshold: ReconstructionThreshold,
    ) -> (MpcContract, Participants, AccountId, DomainId) {
        let participants = gen_participants(num_participants);
        let first_participant_id = participants.participants()[0].0.clone();
        let parameters =
            GovernanceThresholdParameters::new(participants.clone(), governance_threshold).unwrap();
        let domain_id = DomainId::default();
        let mut contract = init_running_with_domain(
            &parameters,
            dtos::DomainConfig {
                id: domain_id,
                protocol: Protocol::CaitSith,
                reconstruction_threshold,
                purpose: DomainPurpose::Sign,
            },
        );
        prepay_and_attest_all_participants(&mut contract);
        (contract, participants, first_participant_id, domain_id)
    }

    /// Installs a voting context for `signer` and casts `proposal`.
    fn vote_params(
        contract: &mut MpcContract,
        signer: &AccountId,
        proposal: &ProposedGovernanceThresholdParameters,
    ) -> Result<(), Error> {
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(signer.clone())
                .predecessor_account_id(signer.clone())
                .attached_deposit(NearToken::ZERO)
                .build()
        );
        contract.vote_new_parameters(dtos::EpochId::new(1), proposal.into_dto_type())
    }

    struct CurrentThresholds {
        participants: usize,
        governance: u64,
        reconstruction: u64,
    }

    struct ProposedThresholds {
        participants: usize,
        governance: u64,
        reconstruction: Option<u64>,
    }

    #[rstest]
    #[case::per_domain_threshold_exceeds_participants(
        CurrentThresholds { participants: 3, governance: 2, reconstruction: 2 },
        ProposedThresholds { participants: 3, governance: 2, reconstruction: Some(4) },
        Err(Error::DomainError(DomainError::ReconstructionThresholdExceedsParticipants {
            reconstruction_threshold: 4,
            participants: ParticipantCount::new(3),
        }))
    )]
    #[case::shrinking_below_governance_threshold(
        CurrentThresholds { participants: 4, governance: 3, reconstruction: 3 },
        ProposedThresholds { participants: 2, governance: 2, reconstruction: None },
        Err(Error::InvalidCandidateSet(InvalidCandidateSet::InsufficientOldParticipants))
    )]
    #[case::signing_threshold_exceeds_participants(
        CurrentThresholds { participants: 3, governance: 2, reconstruction: 2 },
        ProposedThresholds { participants: 3, governance: 4, reconstruction: None },
        Err(Error::InvalidThreshold(InvalidThreshold::MaxRequirementFailed {
            max: ParticipantCount::new(3),
            found: 4,
        }))
    )]
    #[case::per_domain_threshold_within_participant_count(
        CurrentThresholds { participants: 5, governance: 4, reconstruction: 2 },
        ProposedThresholds { participants: 5, governance: 4, reconstruction: Some(4) },
        Ok(())
    )]
    #[case::governance_below_max_reconstruction(
        CurrentThresholds { participants: 5, governance: 4, reconstruction: 4 },
        ProposedThresholds { participants: 5, governance: 3, reconstruction: None },
        Err(Error::InvalidThreshold(InvalidThreshold::BelowReconstructionThreshold {
            reconstruction_threshold: 4,
            governance_threshold: 3,
        }))
    )]
    fn vote_new_parameters__should_validate_proposed_thresholds(
        #[case] current: CurrentThresholds,
        #[case] proposed: ProposedThresholds,
        #[case] expected: Result<(), Error>,
    ) {
        // Given
        let (mut contract, participants, signer, domain_id) = setup_running_contract_with_domain(
            current.participants,
            GovernanceThreshold::new(current.governance),
            ReconstructionThreshold::new(current.reconstruction),
        );
        let per_domain = proposed
            .reconstruction
            .map(|threshold| (domain_id, ReconstructionThreshold::new(threshold)))
            .into_iter()
            .collect();
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new_unvalidated(
                participants.subset(0..proposed.participants),
                GovernanceThreshold::new(proposed.governance),
            ),
            per_domain,
        );

        // When
        let result = vote_params(&mut contract, &signer, &proposal);

        // Then
        assert_eq!(result, expected);
    }

    #[test]
    fn vote_new_parameters__should_reject_a_caller_that_is_not_a_participant() {
        // Given
        let (mut contract, participants, _, _) = setup_running_contract_with_domain(
            3,
            GovernanceThreshold::new(2),
            ReconstructionThreshold::new(2),
        );
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap(),
            BTreeMap::new(),
        );
        assert_matches!(
            contract.tee_state.reverify_and_cleanup_participants(
                proposal.participants(),
                Duration::from_secs(contract.config.tee_upgrade_deadline_duration_seconds),
            ),
            TeeValidationResult::Full
        );
        let outsider: AccountId = "outsider.near".parse().unwrap();

        // When
        let result = vote_params(&mut contract, &outsider, &proposal);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidState(InvalidState::NotParticipant { account_id }) if account_id == outsider
        );
        // Check that vote was not accepted.
        assert_matches!(&contract.protocol_state, ProtocolContractState::Running(_));
        assert!(contract.parameters_votes.is_empty());
    }

    #[test]
    fn vote_add_domains__should_clear_pending_parameter_votes_on_transition() {
        // Given
        let (mut contract, participants, signer, domain_id) = setup_running_contract_with_domain(
            3,
            GovernanceThreshold::new(2),
            ReconstructionThreshold::new(2),
        );
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants.clone(), GovernanceThreshold::new(2))
                .unwrap(),
            BTreeMap::new(),
        );
        vote_params(&mut contract, &signer, &proposal).unwrap();
        assert!(!contract.parameters_votes.is_empty());
        let new_domain = dtos::DomainConfig {
            id: DomainId(domain_id.0 + 1),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        };

        // When
        let mut env = Environment::new(Some(0), None, None);
        for (account_id, _, _) in participants.participants() {
            env.set_signer(account_id);
            contract.vote_add_domains(vec![new_domain.clone()]).unwrap();
        }

        // Then
        assert_matches!(
            &contract.protocol_state,
            ProtocolContractState::Initializing(_)
        );
        assert!(contract.parameters_votes.is_empty());
    }

    /// Installs a context where `account_id` calls as an attested participant, signing with the
    /// account key of its attested node.
    fn attested_context(
        contract: &MpcContract,
        participants: &Participants,
        account_id: &AccountId,
    ) {
        let info = participants.info(account_id).unwrap();
        Environment::new(Some(0), Some(account_id.clone()), None)
            .set_pk(must_get_attested_signer_key(contract, &info.tls_public_key));
    }

    /// Drives a 3-participant Running contract with one domain into Resharing: every
    /// participant votes `proposal`, a key refresh keeping participants and threshold.
    fn resharing_contract_with_domain() -> (
        MpcContract,
        Participants,
        DomainId,
        ProposedGovernanceThresholdParameters,
    ) {
        let (mut contract, participants, _, domain_id) = setup_running_contract_with_domain(
            3,
            GovernanceThreshold::new(2),
            ReconstructionThreshold::new(2),
        );
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants.clone(), GovernanceThreshold::new(2))
                .unwrap(),
            BTreeMap::new(),
        );
        for (account_id, _, _) in participants.participants() {
            vote_params(&mut contract, account_id, &proposal).unwrap();
        }
        assert_matches!(
            &contract.protocol_state,
            ProtocolContractState::Resharing(_)
        );
        (contract, participants, domain_id, proposal)
    }

    /// The tally for `voters` all voting `proposal`.
    fn expected_tally(
        proposal: &ProposedGovernanceThresholdParameters,
        voters: &[&AccountId],
    ) -> dtos::GovernanceThresholdParametersVotes {
        dtos::GovernanceThresholdParametersVotes(BTreeMap::from([(
            proposal.to_proposal_hash(),
            voters
                .iter()
                .map(|voter| dtos::AuthenticatedAccountId((*voter).clone()))
                .collect(),
        )]))
    }

    #[test]
    fn parameters_votes__should_report_pending_votes_by_proposal_hash() {
        // Given
        let (mut contract, participants, signer, _) = setup_running_contract_with_domain(
            3,
            GovernanceThreshold::new(2),
            ReconstructionThreshold::new(2),
        );
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap(),
            BTreeMap::new(),
        );

        // When
        vote_params(&mut contract, &signer, &proposal).unwrap();

        // Then
        assert_eq!(
            contract.parameters_votes(),
            expected_tally(&proposal, &[&signer])
        );
    }

    #[test]
    fn parameters_votes__should_report_re_proposal_votes_while_resharing() {
        // Given
        let (mut contract, participants, _, proposal) = resharing_contract_with_domain();
        let (voter, _, _) = &participants.participants()[0];
        Environment::new(Some(0), Some(voter.clone()), None);

        // When
        contract
            .vote_new_parameters(dtos::EpochId::new(2), (&proposal).into_dto_type())
            .unwrap();

        // Then
        assert_eq!(
            contract.parameters_votes(),
            expected_tally(&proposal, &[voter])
        );
    }

    #[test]
    fn vote_new_parameters__should_record_a_re_proposal_vote_while_resharing() {
        // Given
        let (mut contract, participants, _, proposal) = resharing_contract_with_domain();
        let (voter, _, _) = &participants.participants()[0];
        Environment::new(Some(0), Some(voter.clone()), None);

        // When: a participant re-proposes at the next prospective epoch
        let result =
            contract.vote_new_parameters(dtos::EpochId::new(2), (&proposal).into_dto_type());

        // Then
        assert_matches!(result, Ok(()));
        assert_matches!(
            &contract.protocol_state,
            ProtocolContractState::Resharing(_)
        );
        assert!(!contract.parameters_votes.is_empty());
    }

    #[test]
    fn vote_reshared__should_clear_pending_parameter_votes_on_transition() {
        // Given: a Resharing contract holding a pending re-proposal vote
        let (mut contract, participants, domain_id, proposal) = resharing_contract_with_domain();
        let voter = authenticate_account_as(&participants.participants()[0].0, &participants);
        contract.parameters_votes.vote(&proposal, voter);
        assert!(!contract.parameters_votes.is_empty());

        // When: the resharing completes
        let ProtocolContractState::Resharing(resharing) = &contract.protocol_state else {
            panic!("expected Resharing state");
        };
        let (leader, _) = find_leader(&resharing.resharing_key);
        let key_event_id = KeyEventId {
            attempt_id: AttemptId::new(),
            domain_id,
            epoch_id: EpochId::new(1),
        };
        attested_context(&contract, &participants, &leader);
        contract.start_reshare_instance(key_event_id).unwrap();
        for (account_id, _, _) in participants.participants() {
            attested_context(&contract, &participants, account_id);
            contract.vote_reshared(key_event_id).unwrap();
        }

        // Then
        assert_matches!(&contract.protocol_state, ProtocolContractState::Running(_));
        assert!(contract.parameters_votes.is_empty());
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn vote_new_parameters__should_panic_when_predecessor_differs_from_signer() {
        // Given: a participant whose vote is forwarded through another contract,
        // so signer_account_id (the participant) != predecessor_account_id (the forwarder).
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(3, 2);
        let governance_threshold = GovernanceThreshold::new(2);
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, governance_threshold).unwrap(),
            BTreeMap::new(),
        );

        let ctx = VMContextBuilder::new()
            .signer_account_id(first_participant_id)
            .predecessor_account_id(FORWARDER_ACCOUNT_ID.parse().unwrap())
            .attached_deposit(NearToken::ZERO)
            .build();
        testing_env!(ctx);

        // When / Then: the confused-deputy vote must be rejected before it is recorded.
        contract
            .vote_new_parameters(dtos::EpochId::new(1), (&proposal).into_dto_type())
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn vote_add_domains__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = running_contract_called_by_participant_via_forwarder();
        contract
            .vote_add_domains(vec![])
            .expect("expected panic when predecessor != signer");
    }
}
