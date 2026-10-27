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
    pub fn new_parameters_votes(&self) -> dtos::GovernanceThresholdParametersVotes {
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
        forwarded_participant_call_contract, make_public_key_for_curve, setup_tee_test_contract,
        submit_attestation, submit_valid_attestations,
    };
    use crate::errors::{DomainError, InvalidCandidateSet, InvalidState, InvalidThreshold};
    use crate::primitives::key_state::{AttemptId, EpochId, KeyEventId, KeyForDomain, Keyset};
    use crate::primitives::participants::Participants;
    use crate::primitives::proposal_hash::ToProposalHash;
    use crate::primitives::test_utils::{
        authenticate_account_as, bogus_tee_verifier_account_id, gen_participants,
    };
    use crate::primitives::thresholds::GovernanceThresholdParameters;
    use crate::state::ProtocolContractState;
    use crate::state::key_event::tests::find_leader;
    use crate::tee::test_utils::Environment;
    use dtos::{Curve, DomainId, Protocol, ReconstructionThreshold};
    use near_mpc_contract_interface::types::DomainPurpose;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, NearToken, testing_env};
    use rand::rngs::OsRng;
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

    /// Test that [`MpcContract::vote_new_parameters`] succeeds when all participants have
    /// default TEE status ([`TeeQuoteStatus::None`]). This tests the basic scenario where no
    /// participants have submitted attestation information, and all have the default TEE status
    /// of [`TeeQuoteStatus::None`], which is considered acceptable.
    #[test]
    fn test_vote_new_parameters_succeeds_with_default_tee_status() {
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(3, 2);
        let governance_threshold = GovernanceThreshold::new(2);

        // No attestations submitted - all participants have default TEE status None
        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            governance_threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when all participants have default TEE status None"
        );
    }

    /// Test that [`MpcContract::vote_new_parameters`] succeeds when all participants
    /// submit valid TEE attestations. This tests the scenario where all participants successfully
    /// submit valid attestations through [`MpcContract::submit_participant_info`],
    /// resulting in [`TeeQuoteStatus::Valid`] TEE status for all participants.
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
    /// attestation but is rejected, leaving them with [`TeeQuoteStatus::Invalid`] status, which
    /// combined with valid participants still allows successful voting.
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

        // This should succeed because:
        // - 3 participants have Valid TEE status (from successful attestations)
        // - 1 participant has None TEE status (invalid attestation was rejected)
        // - Both Valid and None are allowed by the TEE validation
        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            governance_threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when participants have Valid or None TEE status (invalid attestations rejected)"
        );
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
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(first_participant_id.clone())
                .predecessor_account_id(first_participant_id.clone())
                .attached_deposit(NearToken::from_near(1))
                .build()
        );

        let parameters =
            GovernanceThresholdParameters::new(participants.clone(), governance_threshold).unwrap();
        let domain_id = DomainId::default();
        let domains = vec![dtos::DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold,
            purpose: DomainPurpose::Sign,
        }];
        let (pk, _) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let keyset = Keyset::new(
            dtos::EpochId::new(0),
            vec![KeyForDomain {
                domain_id,
                key: pk.try_into().unwrap(),
                attempt: AttemptId::new(),
            }],
        );
        let contract = MpcContract::init_running(
            domains,
            1,
            (&keyset).into_dto_type(),
            (&parameters).into_dto_type(),
            bogus_tee_verifier_account_id(),
            None,
        )
        .unwrap();
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

    #[test]
    fn vote_new_parameters__should_reject_when_per_domain_threshold_exceeds_participants() {
        // Given: a Running contract with 3 participants and one domain.
        let (mut contract, participants, signer, domain_id) = setup_running_contract_with_domain(
            3,
            GovernanceThreshold::new(2),
            ReconstructionThreshold::new(2),
        );
        // ...and a proposal raising that domain's reconstruction threshold to 4.
        let mut per_domain = BTreeMap::new();
        per_domain.insert(domain_id, ReconstructionThreshold::new(4));
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap(),
            per_domain,
        );

        // When
        let result = vote_params(&mut contract, &signer, &proposal);

        // Then: 4 > 3 participants, so the guard rejects it.
        assert_matches!(
            result.unwrap_err(),
            Error::DomainError(DomainError::ReconstructionThresholdExceedsParticipants {
                reconstruction_threshold: 4,
                participants: 3,
            })
        );
    }

    #[test]
    fn vote_new_parameters__should_reject_when_shrinking_below_governance_threshold() {
        // Given: a Running contract with 4 participants and a GovernanceThreshold of 3.
        let (mut contract, participants, signer, _domain_id) = setup_running_contract_with_domain(
            4,
            GovernanceThreshold::new(3),
            ReconstructionThreshold::new(3),
        );
        // ...and a proposal that shrinks the participant set to 2 without touching
        // the per-domain thresholds.
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(
                participants.subset(0..2),
                GovernanceThreshold::new(2),
            )
            .unwrap(),
            BTreeMap::new(),
        );

        // When
        let result = vote_params(&mut contract, &signer, &proposal);

        // Then: the candidate-set guard rejects the proposal first, because only 2
        // old participants remain — fewer than the GovernanceThreshold of 3. (Under
        // the GovernanceThreshold >= max(ReconstructionThreshold) invariant this guard
        // always fires before any per-domain ReconstructionThreshold check could.)
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidCandidateSet(InvalidCandidateSet::InsufficientOldParticipants)
        );
    }

    #[test]
    fn vote_new_parameters__should_reject_when_signing_threshold_exceeds_participants() {
        // Given: a Running contract with 3 participants and one domain.
        let (mut contract, participants, signer, _domain_id) = setup_running_contract_with_domain(
            3,
            GovernanceThreshold::new(2),
            ReconstructionThreshold::new(2),
        );
        // ...and a proposal whose signing threshold (4) exceeds the participant set.
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new_unvalidated(
                participants,
                GovernanceThreshold::new(4),
            ),
            BTreeMap::new(),
        );

        // When
        let result = vote_params(&mut contract, &signer, &proposal);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidThreshold(InvalidThreshold::MaxRequirementFailed { max: 3, found: 4 })
        );
    }

    #[test]
    fn vote_new_parameters__should_accept_per_domain_threshold_within_participant_count() {
        // Given: a Running contract with 5 participants (GovernanceThreshold 4) and one domain.
        let (mut contract, participants, signer, domain_id) = setup_running_contract_with_domain(
            5,
            GovernanceThreshold::new(4),
            ReconstructionThreshold::new(2),
        );
        // ...and a proposal raising the domain's reconstruction threshold to 4,
        // which fits the 5 participants and does not exceed the GovernanceThreshold.
        let mut per_domain = BTreeMap::new();
        per_domain.insert(domain_id, ReconstructionThreshold::new(4));
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(4)).unwrap(),
            per_domain,
        );

        // When: a single participant votes (no transition yet).
        let result = vote_params(&mut contract, &signer, &proposal);

        // Then: the guard passes and the vote is recorded.
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn vote_new_parameters__should_reject_governance_below_max_reconstruction() {
        // Given: a Running contract with 5 participants, GovernanceThreshold 4, and a
        // domain whose reconstruction threshold is 4.
        let (mut contract, participants, signer, _domain_id) = setup_running_contract_with_domain(
            5,
            GovernanceThreshold::new(4),
            ReconstructionThreshold::new(4),
        );
        // ...and a proposal lowering the GovernanceThreshold to 3 (valid on its own)
        // while the domain keeps its reconstruction threshold of 4.
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(3)).unwrap(),
            BTreeMap::new(),
        );

        // When
        let result = vote_params(&mut contract, &signer, &proposal);

        // Then: the GovernanceThreshold (3) would fall below the domain's
        // reconstruction threshold (4), so the proposal is rejected.
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidThreshold(InvalidThreshold::BelowReconstructionThreshold {
                reconstruction_threshold: 4,
                governance_threshold: 3,
            })
        );
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

    /// Installs a context where `account_id` calls as an attested participant: `init_running`
    /// mocks each participant's attestation with its TLS key as the account key.
    fn attested_context(participants: &Participants, account_id: &AccountId) {
        let info = participants.info(account_id).unwrap();
        Environment::new(Some(0), Some(account_id.clone()), None)
            .set_pk(near_sdk::PublicKey::from(info.tls_public_key.clone()));
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
    fn new_parameters_votes__should_report_pending_votes_by_proposal_hash() {
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
            contract.new_parameters_votes(),
            expected_tally(&proposal, &[&signer])
        );
    }

    #[test]
    fn new_parameters_votes__should_report_re_proposal_votes_while_resharing() {
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
            contract.new_parameters_votes(),
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
        attested_context(&participants, &leader);
        contract.start_reshare_instance(key_event_id).unwrap();
        for (account_id, _, _) in participants.participants() {
            attested_context(&participants, account_id);
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
            .predecessor_account_id("forwarder.near".parse().unwrap())
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
        let mut contract = forwarded_participant_call_contract();
        contract
            .vote_add_domains(vec![])
            .expect("expected panic when predecessor != signer");
    }
}
