//! Key-event lifecycle: starting and voting through keygen and resharing
//! instances, and cancelling or aborting them.

use crate::crypto_shared::types::PublicKeyExtendedConversionError;
use crate::errors::{Error, InvalidParameters, InvalidState};
use crate::primitives::time::Timestamp;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{Gas, env, log, near};
use std::time::Duration;

#[near]
impl MpcContract {
    /// Starts a new attempt to generate a key for the current domain.
    /// This only succeeds if the signer is the leader (the participant with the lowest ID).
    #[handle_result]
    pub fn start_keygen_instance(&mut self, key_event_id: dtos::KeyEventId) -> Result<(), Error> {
        log!("start_keygen_instance: signer={}", env::signer_account_id(),);

        self.assert_caller_is_attested_participant_and_protocol_active();

        self.protocol_state
            .start_keygen_instance(key_event_id, self.config.key_event_timeout_blocks)
    }

    /// Casts a vote for `public_key` for the attempt identified by `key_event_id`.
    ///
    /// The effect of this method is either:
    ///  - Returns error (which aborts with no changes), if there is no active key generation
    ///    attempt (including if the attempt timed out), if the signer is not a participant, or if
    ///    the key_event_id corresponds to a different domain, different epoch, or different attempt
    ///    from the current key generation attempt.
    ///  - Returns Ok(()), with one of the following changes:
    ///    - A vote has been collected but we don't have enough votes yet.
    ///    - This vote is for a public key that disagrees from an earlier voted public key, causing
    ///      the attempt to abort; another call to [`Self::start_keygen_instance`] is then
    ///      necessary.
    ///    - Everyone has now voted for the same public key; the state transitions into generating a
    ///      key for the next domain.
    ///    - Same as the last case, except that all domains have a generated key now, and the state
    ///      transitions into Running with the newly generated keys.
    #[handle_result]
    pub fn vote_pk(
        &mut self,
        key_event_id: dtos::KeyEventId,
        public_key: dtos::PublicKey,
    ) -> Result<(), Error> {
        log!(
            "vote_pk: signer={}, key_event_id={:?}, public_key={:?}",
            env::signer_account_id(),
            key_event_id,
            public_key,
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        let extended_key =
            public_key
                .try_into()
                .map_err(|err: PublicKeyExtendedConversionError| {
                    InvalidParameters::MalformedPayload {
                        reason: err.to_string(),
                    }
                })?;

        if let Some(new_state) = self.protocol_state.vote_pk(key_event_id, extended_key)? {
            self.protocol_state = new_state;
        }

        Ok(())
    }

    /// Starts a key refresh: a resharing onto the current participants and thresholds.
    ///
    /// Any single participant can call this once
    /// [`key_refresh_period_seconds`](dtos::Config::key_refresh_period_seconds) have passed since
    /// the last completed resharing. Pending [`Self::vote_new_parameters`] votes are kept.
    #[handle_result]
    pub fn trigger_key_refresh(&mut self) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        log!("trigger_key_refresh: signer={}", env::signer_account_id());

        let new_state = self.protocol_state.key_refresh()?;

        let due_at = self
            .last_reshared_at
            .saturating_add(Duration::from_secs(self.config.key_refresh_period_seconds));
        if Timestamp::now() < due_at {
            return Err(InvalidState::KeyRefreshNotDue {
                due_at_seconds: due_at.as_secs(),
            }
            .into());
        }

        self.reverify_participants(new_state.active_participants())?;

        self.protocol_state = new_state;
        Ok(())
    }

    /// Starts a new attempt to reshare the key for the current domain.
    /// This only succeeds if the signer is the leader (the participant with the lowest ID).
    #[handle_result]
    pub fn start_reshare_instance(&mut self, key_event_id: dtos::KeyEventId) -> Result<(), Error> {
        log!(
            "start_reshare_instance: signer={}",
            env::signer_account_id()
        );

        self.assert_caller_is_attested_participant_and_protocol_active();
        self.protocol_state
            .start_reshare_instance(key_event_id, self.config.key_event_timeout_blocks)
    }

    /// Casts a vote for the successful resharing of the attempt identified by `key_event_id`.
    ///
    /// The effect of this method is either:
    ///  - Returns error (which aborts with no changes), if there is no active key resharing attempt
    ///    (including if the attempt timed out), if the signer is not a participant, or if the
    ///    key_event_id corresponds to a different domain, different epoch, or different attempt
    ///    from the current key resharing attempt.
    ///  - Returns Ok(()), with one of the following changes:
    ///    - A vote has been collected but we don't have enough votes yet.
    ///    - Everyone has now voted; the state transitions into resharing the key for the next
    ///      domain.
    ///    - Same as the last case, except that all domains' keys have been reshared now, and the
    ///      state transitions into Running with the newly reshared keys.
    #[handle_result]
    pub fn vote_reshared(&mut self, key_event_id: dtos::KeyEventId) -> Result<(), Error> {
        log!(
            "vote_reshared: signer={}, resharing_id={:?}",
            env::signer_account_id(),
            key_event_id,
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        let previous_parameters = self.protocol_state.threshold_parameters_or_panic().clone();
        let previous_domains = self.protocol_state.domain_registry().ok().cloned();
        if let Some(new_state) = self.protocol_state.vote_reshared(key_event_id)? {
            // Resharing has concluded, transition to running state
            self.protocol_state = new_state;
            self.last_reshared_at = Timestamp::now();
            // Pending votes were cast against the previous parameters.
            if *self.protocol_state.threshold_parameters_or_panic() != previous_parameters
                || self.protocol_state.domain_registry().ok() != previous_domains.as_ref()
            {
                self.parameters_votes.clear();
            }
            let participants = self.protocol_state.active_participants();
            self.add_domains_votes
                .retain_votes(|p| participants.is_participant(p));
            self.recompute_available_foreign_chains();

            // Spawn a promise to clean up votes from non-participants.
            // Note: MpcContract::vote_contract_update uses filtering to ensure correctness even if this cleanup fails.
            Self::ext_self()
                .with_static_gas(Gas::from_tgas(
                    self.config.remove_non_participant_update_votes_tera_gas,
                ))
                .with_unused_gas_weight(0)
                .remove_non_participant_contract_update_votes()
                .detach();
            // Spawn a promise to drop votes cast by non-participants.
            Self::ext_self()
                .with_static_gas(Gas::from_tgas(self.config.clean_tee_status_tera_gas))
                .with_unused_gas_weight(0)
                .clean_tee_status()
                .detach();
            // Spawn a bounded sweep over stored attestations to prune invalid / expired entries.
            Self::ext_self()
                .with_static_gas(Gas::from_tgas(
                    self.config.clean_invalid_attestations_tera_gas,
                ))
                .with_unused_gas_weight(0)
                .clean_invalid_attestations(RESHARE_CLEAN_INVALID_ATTESTATIONS_MAX_SCAN)
                .detach();
            // Spawn a promise to clean up orphaned node migrations for non-participants
            Self::ext_self()
                .with_static_gas(Gas::from_tgas(
                    self.config.cleanup_orphaned_node_migrations_tera_gas,
                ))
                .with_unused_gas_weight(0)
                .cleanup_orphaned_node_migrations()
                .detach();
            // Spawn a promise to clean up foreign chain data for non-participants
            Self::ext_self()
                .with_static_gas(Gas::from_tgas(
                    self.config.clean_foreign_chain_data_tera_gas,
                ))
                .with_unused_gas_weight(0)
                .clean_foreign_chain_data()
                .detach();
            // Spawn a promise to drop verifier-change votes cast by non-participants
            Self::ext_self()
                .with_static_gas(Gas::from_tgas(
                    self.config
                        .remove_non_participant_tee_verifier_votes_tera_gas,
                ))
                .with_unused_gas_weight(0)
                .remove_non_participant_tee_verifier_votes()
                .detach();
        }

        Ok(())
    }

    /// Casts a vote to cancel the current key resharing. If a threshold number of unique
    /// votes are collected to cancel the resharing, the contract state will revert back to the
    /// previous running state.
    ///
    /// - This method is idempotent, meaning a single account can not make more than one vote.
    /// - Only nodes from the previous running state are allowed to vote.
    ///
    /// Return value:
    /// - [Ok] if the vote was successfully collected.
    /// - [Err] if:
    ///     - The signer is not a participant in the previous running state.
    ///     - The contract is not in a resharing state.
    #[handle_result]
    pub fn vote_cancel_resharing(&mut self) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        log!("vote_cancel_resharing: signer={}", env::signer_account_id());

        if let Some(new_state) = self.protocol_state.vote_cancel_resharing()? {
            self.protocol_state = new_state;
        }

        Ok(())
    }

    /// Casts a vote to cancel key generation. Any keys that have already been generated
    /// are kept and we transition into Running state; remaining domains are permanently deleted.
    /// Deleted domain IDs cannot be reused again in future calls to vote_add_domains.
    ///
    /// A next_domain_id that matches that in the state's domains struct must be passed in. This is
    /// to prevent stale requests from accidentally cancelling a future key generation state.
    #[handle_result]
    pub fn vote_cancel_keygen(&mut self, next_domain_id: dtos::DomainId) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        log!("vote_cancel_keygen: signer={}", env::signer_account_id());

        if let Some(new_state) = self.protocol_state.vote_cancel_keygen(next_domain_id)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    /// Casts a vote to abort the current key event instance. If succesful, the contract aborts the
    /// instance and a new instance with the next attempt_id can be started.
    #[handle_result]
    pub fn vote_abort_key_event_instance(
        &mut self,
        key_event_id: dtos::KeyEventId,
    ) -> Result<(), Error> {
        log!(
            "vote_abort_key_event_instance: signer={}",
            env::signer_account_id()
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        self.protocol_state
            .vote_abort_key_event_instance(key_event_id)
    }
}

/// Entries to scan in the post-reshare `clean_invalid_attestations` sweep. External callers
/// may pick a different value; this only governs the automatic invocation.
///
/// Sized against [`crate::config::Config::clean_invalid_attestations_tera_gas`]: scanning an
/// entry costs gas whether or not it is removed, so raising this without raising that
/// overruns the budget.
const RESHARE_CLEAN_INVALID_ATTESTATIONS_MAX_SCAN: u32 = 30;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::MpcContract;
    use crate::api::test_utils::{
        init_running_with_domain, initializing_state, must_get_attested_signer_key,
        prepay_and_attest_all_participants, resharing_state,
        running_contract_called_by_participant_via_forwarder, setup_tee_test_contract, vote_params,
    };
    use crate::errors::{Error, InvalidParameters, InvalidState};
    use crate::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use crate::primitives::participants::Participants;
    use crate::primitives::proposal_hash::ToProposalHash;
    use crate::primitives::test_utils::{authenticate_account_as, gen_participants};
    use crate::primitives::thresholds::{
        GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
    };
    use crate::state::ProtocolContractState;
    use crate::state::key_event::tests::find_leader;
    use crate::tee::test_utils::{NANOS_PER_SECOND, set_block_secs};
    use mpc_attestation::attestation::MOCK_EXPIRATION_DURATION_SECONDS;
    use near_account_id::AccountId;
    use near_mpc_contract_interface::types::{
        DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
    };
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rstest::rstest;
    use std::assert_matches;
    use std::collections::{BTreeMap, BTreeSet};

    const INITIALIZED_AT_SECONDS: u64 = 1_000_000;

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn vote_cancel_resharing__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = running_contract_called_by_participant_via_forwarder();
        contract
            .vote_cancel_resharing()
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn vote_cancel_keygen__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = running_contract_called_by_participant_via_forwarder();
        contract
            .vote_cancel_keygen(DomainId(0))
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn trigger_key_refresh__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = running_contract_called_by_participant_via_forwarder();
        contract
            .trigger_key_refresh()
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    fn trigger_key_refresh__should_start_resharing_onto_current_parameters_when_due() {
        // Given
        let (mut contract, participants) = running_contract_with_key();
        let parameters = contract
            .protocol_state
            .threshold_parameters_or_panic()
            .clone();
        call_as(
            &first_account(&participants),
            refresh_due_at_seconds(&contract),
        );

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_eq!(result, Ok(()));
        let ProtocolContractState::Resharing(resharing) = &contract.protocol_state else {
            panic!("expected Resharing state");
        };
        assert_eq!(resharing.resharing_key.proposed_parameters(), &parameters);
        assert_eq!(resharing.previous_running_state.parameters, parameters);
        assert_eq!(resharing.prospective_epoch_id(), EpochId::new(1));
        assert!(resharing.per_domain_thresholds.is_empty());
    }

    #[test]
    fn trigger_key_refresh__should_fail_before_refresh_is_due() {
        // Given
        let (mut contract, participants) = running_contract_with_key();
        let due_at_seconds = refresh_due_at_seconds(&contract);
        call_as(&first_account(&participants), due_at_seconds - 1);

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_eq!(
            result,
            Err(InvalidState::KeyRefreshNotDue { due_at_seconds }.into())
        );
        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));
    }

    #[test]
    fn trigger_key_refresh__should_fail_for_non_participant() {
        // Given
        let (mut contract, _) = running_contract_with_key();
        let account_id: AccountId = "outsider.near".parse().unwrap();
        call_as(&account_id, refresh_due_at_seconds(&contract));

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_eq!(
            result,
            Err(InvalidState::NotParticipant { account_id }.into())
        );
    }

    #[rstest]
    #[case::resharing(resharing_state())]
    #[case::initializing(initializing_state())]
    fn trigger_key_refresh__should_fail_when_not_running(
        #[case] protocol_state: ProtocolContractState,
    ) {
        // Given
        let mut contract = MpcContract::new_from_protocol_state(protocol_state);

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_eq!(result, Err(InvalidState::ProtocolStateNotRunning.into()));
    }

    #[test]
    fn trigger_key_refresh__should_fail_without_keys() {
        // Given
        set_block_secs(INITIALIZED_AT_SECONDS);
        let (mut contract, _, signer) = setup_tee_test_contract(3, 2);
        call_as(&signer, refresh_due_at_seconds(&contract));

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_eq!(result, Err(InvalidState::NoKeysToRefresh.into()));
    }

    #[test]
    fn trigger_key_refresh__should_fail_when_a_participant_has_no_valid_attestation() {
        // Given
        set_block_secs(INITIALIZED_AT_SECONDS);
        let participants = gen_participants(3);
        let mut contract = init_running_with_domain(&parameters_of(&participants), domain());
        call_as(
            &first_account(&participants),
            refresh_due_at_seconds(&contract),
        );

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(
                InvalidParameters::InvalidTeeRemoteAttestation { .. }
            ))
        );
        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));
    }

    #[test]
    fn trigger_key_refresh__should_keep_pending_parameters_votes() {
        // Given
        let (mut contract, participants) = running_contract_with_key();
        let signer = first_account(&participants);
        let proposal = ProposedGovernanceThresholdParameters::new(
            parameters_of(&participants.subset(0..2)),
            BTreeMap::new(),
        );
        vote_params(&mut contract, &signer, &proposal).unwrap();
        call_as(&signer, refresh_due_at_seconds(&contract));

        // When
        let result = contract.trigger_key_refresh();

        // Then
        assert_eq!(result, Ok(()));
        assert_eq!(
            contract.parameters_votes.all(),
            BTreeMap::from([(
                proposal.to_proposal_hash(),
                BTreeSet::from([authenticate_account_as(&signer, &participants)])
            )])
        );
    }

    #[test]
    fn vote_reshared__should_record_when_the_resharing_completed() {
        // Given
        let (mut contract, participants) = running_contract_with_key();
        let triggered_at_seconds = refresh_due_at_seconds(&contract);
        let completed_at_seconds = triggered_at_seconds + 60;
        call_as(&first_account(&participants), triggered_at_seconds);
        contract.trigger_key_refresh().unwrap();
        let ProtocolContractState::Resharing(resharing) = &contract.protocol_state else {
            panic!("expected Resharing state");
        };
        let (leader, _) = find_leader(&resharing.resharing_key);
        let key_event_id = KeyEventId {
            epoch_id: EpochId::new(1),
            domain_id: domain().id,
            attempt_id: AttemptId::new(),
        };
        call_as_node_of(&contract, &participants, &leader, completed_at_seconds);
        contract.start_reshare_instance(key_event_id).unwrap();

        // When
        for (account_id, _, _) in participants.participants() {
            call_as_node_of(&contract, &participants, account_id, completed_at_seconds);
            contract.vote_reshared(key_event_id).unwrap();
        }

        // Then
        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));
        assert_eq!(
            contract.last_reshared_timestamp_seconds(),
            completed_at_seconds
        );
    }

    fn running_contract_with_key() -> (MpcContract, Participants) {
        set_block_secs(INITIALIZED_AT_SECONDS);
        let participants = gen_participants(3);
        let mut contract = init_running_with_domain(&parameters_of(&participants), domain());
        // The mock attestations must outlive the refresh period.
        contract.config.key_refresh_period_seconds = MOCK_EXPIRATION_DURATION_SECONDS / 2;
        prepay_and_attest_all_participants(&mut contract);
        (contract, participants)
    }

    fn parameters_of(participants: &Participants) -> GovernanceThresholdParameters {
        GovernanceThresholdParameters::new(participants.clone(), GovernanceThreshold::new(2))
            .unwrap()
    }

    fn domain() -> DomainConfig {
        DomainConfig {
            id: DomainId::default(),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }
    }

    fn first_account(participants: &Participants) -> AccountId {
        participants.participants()[0].0.clone()
    }

    fn refresh_due_at_seconds(contract: &MpcContract) -> u64 {
        INITIALIZED_AT_SECONDS + contract.config.key_refresh_period_seconds
    }

    fn call_as(account_id: &AccountId, block_seconds: u64) {
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .block_timestamp(block_seconds * NANOS_PER_SECOND)
                .build()
        );
    }

    fn call_as_node_of(
        contract: &MpcContract,
        participants: &Participants,
        account_id: &AccountId,
        block_seconds: u64,
    ) {
        let info = participants.info(account_id).unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .signer_account_pk(must_get_attested_signer_key(contract, &info.tls_public_key))
                .block_timestamp(block_seconds * NANOS_PER_SECOND)
                .build()
        );
    }
}
