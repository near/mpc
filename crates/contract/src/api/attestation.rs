//! TEE attestation lifecycle

use crate::dto_mapping::{IntoInterfaceType, TryIntoContractType};
use crate::errors::{Error, InvalidParameters, InvalidState, TeeError};
use crate::primitives::domain::max_reconstruction_threshold;
use crate::primitives::key_state::AuthenticatedParticipantId;
use crate::primitives::thresholds::{
    GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
};
use crate::state::ProtocolContractState;
use crate::tee::tee_state::{
    AttestationSubmissionError, NodeId, ParticipantInsertion, TeeValidationResult,
};
use crate::tee::verification_context::VerificationContext;
use crate::{MpcContract, MpcContractExt};
use mpc_attestation::attestation::{Attestation, DstackAttestation};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{AccountId, Gas, NearToken, Promise, PromiseError, PromiseOrValue, env, log, near};
use std::collections::BTreeMap;
use std::time::Duration;
use tee_verifier_interface::{VerificationResult, VerifiedReport};

#[near]
impl MpcContract {
    pub fn available_attestation_grants(&self, account_id: AccountId) -> u32 {
        self.grants_for(&account_id)
    }

    fn grants_for(&self, account_id: &AccountId) -> u32 {
        self.available_attestation_grants
            .get(account_id)
            .copied()
            .unwrap_or(0)
    }

    /// Buys `grants` attestation-storage grants for `account_id`.
    ///
    /// Permissionless, which is what lets an operator fund a node whose function-call key
    /// cannot attach a deposit. Requires exactly the fee times `grants`; no refunds, no
    /// withdrawal.
    #[payable]
    #[handle_result]
    pub fn prepay_attestation_storage(
        &mut self,
        account_id: AccountId,
        grants: u32,
    ) -> Result<(), Error> {
        if grants == 0 {
            return Err(InvalidParameters::MalformedPayload {
                reason: "grants must be greater than zero".to_string(),
            }
            .into());
        }

        let required = self
            .attestation_storage_fee()
            .as_yoctonear()
            .checked_mul(u128::from(grants))
            .ok_or(InvalidParameters::MalformedPayload {
                reason: "requested grants overflow the fee calculation".to_string(),
            })?;
        let attached = env::attached_deposit().as_yoctonear();
        if attached != required {
            return Err(InvalidParameters::UnexpectedDeposit { attached, required }.into());
        }

        let available = self.grants_for(&account_id);
        let credited =
            available
                .checked_add(grants)
                .ok_or(InvalidParameters::MalformedPayload {
                    reason: "grant counter would overflow".to_string(),
                })?;
        self.available_attestation_grants
            .insert(account_id.clone(), credited);

        Ok(())
    }

    /// Submit a TEE attestation for a current or prospective participant.
    ///
    /// - [`Attestation::Mock`] is verified synchronously.
    /// - [`Attestation::Dstack`] is verified asynchronously via a cross-contract
    ///   `verify_quote` call, with [`Self::resolve_verification`] chained as its
    ///   callback to run the post-DCAP checks and store the attestation.
    ///
    /// A node submits with no deposit via its function-call access key. Storing a *new* entry
    /// consumes one attestation-storage grant, prepaid for the node's account by whoever
    /// onboards it; a re-attestation under a key the account already owns consumes none.
    #[handle_result]
    pub fn submit_participant_info(
        &mut self,
        proposed_participant_attestation: dtos::Attestation,
        tls_public_key: dtos::Ed25519PublicKey,
    ) -> Result<PromiseOrValue<()>, Error> {
        let proposed_participant_attestation =
            proposed_participant_attestation.try_into_contract_type()?;

        let account_key = env::signer_account_pk();
        let account_id = Self::assert_caller_is_signer();

        log!(
            "submit_participant_info: signer={}, proposed_participant_attestation={:?}, account_key={:?}",
            account_id,
            proposed_participant_attestation,
            account_key
        );

        // The node always signs submissions with an Ed25519 key
        // (`near_signer_key`), so the signer key here is Ed25519 in practice.
        // Reject non-Ed25519 signer keys rather than silently storing a value
        // we could never match against in `is_caller_an_attested_participant`.
        let account_public_key = dtos::Ed25519PublicKey::try_from(&account_key).map_err(|_| {
            InvalidParameters::InvalidTeeRemoteAttestation {
                reason: "signer account key must be Ed25519".to_string(),
            }
        })?;

        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key,
            account_public_key,
        };

        // Before any verification: an ungranted or unauthorised submission stops here.
        self.assert_attestation_storage_grant_available(
            &node_id.account_id,
            &node_id.tls_public_key,
        )?;

        match proposed_participant_attestation {
            Attestation::Mock(mock) => {
                let tee_upgrade_deadline_duration =
                    Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
                let insertion = self.tee_state.verify_and_store_mock(
                    node_id.clone(),
                    mock,
                    tee_upgrade_deadline_duration,
                )?;
                if matches!(insertion, ParticipantInsertion::NewlyInsertedParticipant) {
                    self.consume_attestation_storage_grant(&node_id.account_id);
                }

                // A `WithConstraints` mock may reference a launcher hash; refresh-on-use keeps
                // it alive, matching the dstack path. No-op for mocks without a launcher.
                // Capability token: only a current participant may keep its launcher hash alive.
                let authenticated_participant = self
                    .protocol_state
                    .threshold_parameters()
                    .ok()
                    .and_then(|params| AuthenticatedParticipantId::new(params.participants()).ok());
                if let Some(authenticated_participant) = &authenticated_participant {
                    let launcher_unused_ttl =
                        Duration::from_secs(self.config.launcher_hash_unused_ttl_seconds);
                    self.tee_state.refresh_launcher_usage(
                        &node_id.tls_public_key,
                        authenticated_participant,
                        launcher_unused_ttl,
                    );
                }

                Ok(PromiseOrValue::Value(()))
            }
            Attestation::Dstack(attestation) => Ok(PromiseOrValue::Promise(
                self.submit_dstack_attestation(node_id, attestation)?,
            )),
        }
    }

    /// Read from `config()` by operators; deliberately not its own view.
    fn attestation_storage_fee(&self) -> NearToken {
        NearToken::from_millinear(u128::from(self.config.attestation_storage_fee_millinear))
    }

    fn attestation_submission_needs_grant(
        &self,
        account_id: &AccountId,
        tls_public_key: &dtos::Ed25519PublicKey,
    ) -> Result<bool, Error> {
        match self.tee_state.attestation_owner(tls_public_key) {
            Some(owner) if &owner == account_id => Ok(false),
            Some(_) => Err(AttestationSubmissionError::TlsKeyOwnedByOtherAccount.into()),
            None => Ok(true),
        }
    }

    fn assert_attestation_storage_grant_available(
        &self,
        account_id: &AccountId,
        tls_public_key: &dtos::Ed25519PublicKey,
    ) -> Result<(), Error> {
        if self.attestation_submission_needs_grant(account_id, tls_public_key)?
            && self.grants_for(account_id) == 0
        {
            return Err(InvalidParameters::NoAttestationStorageGrant {
                account_id: account_id.to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Consumes one grant for `account_id`.
    fn consume_attestation_storage_grant(&mut self, account_id: &AccountId) {
        let remaining = self
            .grants_for(account_id)
            .checked_sub(1)
            .expect("caller must establish an available grant before consuming one");
        if remaining == 0 {
            self.available_attestation_grants.remove(account_id);
        } else {
            self.available_attestation_grants
                .insert(account_id.clone(), remaining);
        }
    }

    fn return_attestation_storage_grant(&mut self, account_id: &AccountId) {
        let available = self.grants_for(account_id);
        // Checked, not saturating: at `u32::MAX` a returned grant would be dropped silently.
        let Some(returned) = available.checked_add(1) else {
            log!("grant counter for {account_id} is saturated; not returning a grant");
            return;
        };
        self.available_attestation_grants
            .insert(account_id.clone(), returned);
    }

    /// Async [`Attestation::Dstack`] submission: spawns a promise calling
    /// `verify_quote` on the trusted verifier contract, with
    /// [`Self::resolve_verification`] chained as its callback.
    fn submit_dstack_attestation(
        &mut self,
        node_id: NodeId,
        attestation: DstackAttestation,
    ) -> Result<Promise, Error> {
        Ok(Promise::new(self.tee_verifier_account_id.clone())
            .function_call(
                method_names::VERIFY_QUOTE.to_string(),
                borsh::to_vec(&(&attestation.quote, &attestation.collateral))
                    .expect("borsh serialization of verify_quote args must succeed"),
                NearToken::from_near(0),
                Gas::from_tgas(self.config.verifier_tera_gas),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(self.config.resolve_verification_tera_gas))
                    .resolve_verification(VerificationContext {
                        node_id,
                        tcb_info: attestation.tcb_info,
                    }),
            ))
    }

    #[handle_result]
    pub fn get_attestation(
        &self,
        tls_public_key: dtos::Ed25519PublicKey,
    ) -> Result<Option<dtos::VerifiedAttestation>, Error> {
        Ok(self
            .tee_state
            .stored_attestations
            .get(&tls_public_key)
            .map(|node_attestation| {
                node_attestation
                    .verified_attestation
                    .clone()
                    .into_dto_type()
            }))
    }

    /// Returns all accounts that have TEE attestations stored in the contract.
    /// Note: This includes both current protocol participants and accounts that may have
    /// submitted TEE information but are not currently part of the active participant set.
    pub fn get_tee_accounts(&self) -> Vec<dtos::NodeId> {
        log!("get_tee_accounts");
        self.tee_state.get_tee_accounts()
    }

    /// Verifies if all current participants have an accepted TEE state.
    /// Automatically enters a resharing, in case one or more participants do not have an accepted
    /// TEE state.
    /// Returns `false` and stops the contract from accepting new signature requests or responses,
    /// in case less than `threshold` participants run in an accepted TEE State.
    #[handle_result]
    pub fn verify_tee(&mut self) -> Result<bool, Error> {
        log!("verify_tee: signer={}", env::signer_account_id());
        // Caller must be a participant (node or operator).
        self.voter_or_panic();
        let ProtocolContractState::Running(running_state) = &mut self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };
        let current_params = running_state.parameters.clone();

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        match self.tee_state.reverify_and_cleanup_participants(
            current_params.participants(),
            tee_upgrade_deadline_duration,
        ) {
            TeeValidationResult::Full => {
                self.accept_requests = true;
                log!("All participants have an accepted Tee status");
                Ok(true)
            }
            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            } => {
                let remaining = participants_with_valid_attestation.len();
                // Defense in depth: the surviving participant set must keep the full
                // threshold relation intact — the GovernanceThreshold must still sit
                // within its bounds for the smaller set (in particular it must not
                // exceed the remaining participant count or the upper cap) and must
                // remain at least every domain's ReconstructionThreshold (the kickout
                // keeps the existing per-domain thresholds). Otherwise we refuse and
                // wait for manual intervention.
                let max_reconstruction_threshold =
                    max_reconstruction_threshold(running_state.domains.domains());
                if let Err(err) =
                    GovernanceThresholdParameters::validate_governance_against_reconstruction(
                        u64::try_from(remaining).expect("participant count fits in u64"),
                        current_params.threshold(),
                        max_reconstruction_threshold,
                    )
                {
                    log!(
                        "Kicking out participants with an invalid TEE status would break the threshold relation ({:?}); {} participants remain with a valid TEE status. This requires manual intervention. We will not accept new signature requests as a safety precaution.",
                        err,
                        remaining,
                    );
                    self.accept_requests = false;
                    return Ok(false);
                }

                // here, we set it to true, because at this point, we have at least `threshold`
                // number of participants with an accepted Tee status.
                self.accept_requests = true;

                // do we want to adjust the threshold?
                //let n_participants_new = new_participants.len();
                //let new_threshold = (3 * n_participants_new + 4) / 5; // minimum 60%
                //let new_threshold = new_threshold.max(2); // but also minimum 2
                let new_threshold = usize::try_from(current_params.threshold().value())
                    .expect("threshold value fits in usize");

                let threshold_parameters = GovernanceThresholdParameters::new(
                    participants_with_valid_attestation,
                    GovernanceThreshold::new(new_threshold as u64),
                )
                .expect("Require valid threshold parameters"); // this should never happen.
                current_params.validate_incoming_proposal(&threshold_parameters)?;
                // This resharing only changes the participant set, so the
                // per-domain reconstruction-threshold updates map is empty.
                let proposed_parameters = ProposedGovernanceThresholdParameters::new(
                    threshold_parameters,
                    BTreeMap::new(),
                );
                let res = running_state.transition_to_resharing_no_checks(&proposed_parameters);
                if let Some(resharing) = res {
                    self.protocol_state = ProtocolContractState::Resharing(resharing);
                }

                Ok(true)
            }
        }
    }

    /// Prunes up to `max_scan` stored attestations that fail re-verification (expired or
    /// referencing stale whitelists), returning one attestation-storage grant to the owner of
    /// each entry removed. Returns the number of entries removed. Callable by anyone while the
    /// protocol is in [`Running`](ProtocolContractState::Running).
    #[handle_result]
    pub fn clean_invalid_attestations(&mut self, max_scan: u32) -> Result<u32, Error> {
        log!(
            "clean_invalid_attestations: signer={}, max_scan={}",
            env::signer_account_id(),
            max_scan
        );
        // Running-only: keygen / resharing may reference attestations that have not yet
        // been activated, so cleanup is off-limits during those phases.
        if !matches!(self.protocol_state, ProtocolContractState::Running(_)) {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
        let removed_entry_owners = self
            .tee_state
            .clean_invalid_attestations(tee_upgrade_deadline_duration, max_scan as usize);
        for account_id in &removed_entry_owners {
            self.return_attestation_storage_grant(account_id);
        }
        Ok(u32::try_from(removed_entry_owners.len())
            .expect("u32 should always be convertible from usize on wasm32"))
    }

    /// Verify-quote callback: on a verifier verdict it runs the post-DCAP checks and stores the
    /// attestation, consuming one attestation-storage grant if the entry is new. On any failure
    /// it fails the submitter's transaction.
    #[private]
    pub fn resolve_verification(
        &mut self,
        #[serializer(borsh)] context: VerificationContext,
        #[serializer(borsh)]
        #[callback_result]
        result: Result<VerificationResult, PromiseError>,
    ) -> PromiseOrValue<()> {
        let account_id = context.node_id.account_id.clone();
        log!("resolve_verification: account_id={account_id}");

        let attestation_result = match result {
            Ok(VerificationResult::Verified(report)) => {
                self.verify_post_dcap_and_store(&context, &report)
            }
            Ok(VerificationResult::Rejected(reason)) => {
                log!("verifier rejected quote for {account_id}: {reason}");
                Err(TeeError::QuoteRejected {
                    reason: reason.to_string(),
                }
                .into())
            }
            // No verdict (verifier unreachable, panicked, or out of gas)
            Err(promise_err) => {
                log!("verifier did not answer for {account_id}: {promise_err:?}");
                Err(TeeError::VerifierUnavailable.into())
            }
        };

        match attestation_result {
            Ok(()) => PromiseOrValue::Value(()),
            Err(err) => {
                // Fail the submitter's transaction from a separate receipt so any prior state
                // commits (a panic here would roll it back)
                let promise = Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(
                        self.config.fail_attestation_submission_tera_gas,
                    ))
                    .fail_attestation_submission(err.to_string());
                PromiseOrValue::Promise(promise.as_return())
            }
        }
    }

    /// Runs the post-DCAP checks and stores the attestation for a
    /// [`VerificationResult::Verified`] response. Re-checks that a grant is available before
    /// storing, since this runs a receipt later than the submission that reserved it.
    fn verify_post_dcap_and_store(
        &mut self,
        context: &VerificationContext,
        report: &VerifiedReport,
    ) -> Result<(), Error> {
        let account_id = context.node_id.account_id.clone();
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
        let launcher_unused_ttl = Duration::from_secs(self.config.launcher_hash_unused_ttl_seconds);

        // Capability token: only a current participant may keep its launcher hash alive.
        // The signer is preserved across the verifier promise, so this reflects the
        // original submitter.
        let authenticated_participant = self
            .protocol_state
            .threshold_parameters()
            .ok()
            .and_then(|params| AuthenticatedParticipantId::new(params.participants()).ok());
        let tls_public_key_for_refresh = context.node_id.tls_public_key.clone();

        self.assert_attestation_storage_grant_available(
            &account_id,
            &context.node_id.tls_public_key,
        )?;

        let insertion = match self.tee_state.verify_and_store_dstack(
            context.node_id.clone(),
            &context.tcb_info,
            report,
            tee_upgrade_deadline_duration,
        ) {
            Ok(insertion) => insertion,
            Err(err) => {
                log!("post-DCAP check failed for {account_id}: {err}");
                return Err(err.into());
            }
        };
        if matches!(insertion, ParticipantInsertion::NewlyInsertedParticipant) {
            self.consume_attestation_storage_grant(&account_id);
        }

        // Refresh-on-use: a current participant's successful submission keeps the launcher
        // hash its attestation references from expiring.
        if let Some(participant) = &authenticated_participant {
            self.tee_state.refresh_launcher_usage(
                &tls_public_key_for_refresh,
                participant,
                launcher_unused_ttl,
            );
        }

        Ok(())
    }

    #[private]
    pub fn fail_attestation_submission(reason: String) {
        log!("fail_attestation_submission: {reason}");
        env::panic_str(&reason);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{
        basic_setup, bogus_tee_verifier_account_id, make_public_key_for_curve,
        setup_tee_test_contract, submit_valid_attestations,
    };
    use crate::config::Config;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
    use crate::primitives::participants::{ParticipantId, Participants};
    use crate::primitives::test_utils::{
        bogus_ed25519_near_public_key, bogus_ed25519_public_key, create_node_id, gen_participants,
    };
    use crate::state::key_event::KeyEvent;
    use crate::state::resharing::ResharingContractState;
    use crate::tee::tee_state::{NodeAttestation, TeeState};
    use crate::tee::test_utils::whitelist_dstack_measurements;
    use assert_matches::assert_matches;
    use dtos::{
        Attestation, Curve, DomainConfig, DomainId, Ed25519PublicKey, MockAttestation, Protocol,
        ReconstructionThreshold,
    };
    use mpc_attestation::attestation::{
        MockAttestation as MpcMockAttestation, ValidatedDstackAttestation, VerifiedAttestation,
        default_measurements,
    };
    use mpc_primitives::hash::LauncherImageHash;
    use near_mpc_contract_interface::types::DomainPurpose;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rand::rngs::OsRng;
    use rstest::rstest;
    use std::collections::HashSet;
    use std::panic;
    use test_utils::attestation::{
        VALID_ATTESTATION_TIMESTAMP, account_key, image_digest, launcher_compose_digest,
        launcher_image_hash, mock_tcb_info, p2p_tls_key, verified_report,
    };

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn test_submit_participant_info_panics_if_predecessor_differs() {
        let (mut contract, participants, _first_participant_id) = setup_tee_test_contract(3, 2);

        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        let (participant_id, _, participant_info) = participants
            .participants()
            .first()
            .expect("at least one participant")
            .clone();

        let valid_attestation = Attestation::Mock(MockAttestation::Valid);

        // Case: signer != predecessor — should panic
        let ctx = VMContextBuilder::new()
            .signer_account_id(participant_id.clone())
            .predecessor_account_id("outsider.near".parse().unwrap())
            .build();
        testing_env!(ctx);

        let _ = contract
            .submit_participant_info(valid_attestation, participant_info.tls_public_key.clone())
            .expect("Expected panic if predecessor != signer");
    }

    fn dstack_verification_setup() -> (MpcContract, VerificationContext) {
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let contract_account_id = env::current_account_id();
        let context = VMContextBuilder::new()
            .current_account_id(contract_account_id.clone())
            .predecessor_account_id(contract_account_id)
            .block_timestamp(VALID_ATTESTATION_TIMESTAMP * 1_000_000_000)
            .build();
        testing_env!(context);

        contract.tee_state = TeeState::default();
        whitelist_dstack_measurements(
            &mut contract.tee_state,
            image_digest(),
            launcher_image_hash(),
            Some(launcher_compose_digest()),
        );

        // Storing a new entry consumes a grant, so stand in for the operator's prepayment.
        contract
            .available_attestation_grants
            .insert("alice.near".parse().unwrap(), 1);

        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: Ed25519PublicKey(p2p_tls_key()),
            account_public_key: Ed25519PublicKey(account_key()),
        };
        (
            contract,
            VerificationContext {
                node_id,
                tcb_info: mock_tcb_info(),
            },
        )
    }

    /// The deposit must be exactly `fee × grants`, which is what makes a remainder — and so a
    /// refund path — impossible.
    #[rstest]
    #[case::one_yocto_short(-1)]
    #[case::one_yocto_over(1)]
    fn prepay_attestation_storage__should_reject_a_deposit_that_is_not_an_exact_multiple(
        #[case] offset: i128,
    ) {
        // Given
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let node: AccountId = "newcomer.near".parse().unwrap();
        let fee = u128::from(contract.config().attestation_storage_fee_millinear);
        let exact = NearToken::from_millinear(fee * 2).as_yoctonear();
        let attached = NearToken::from_yoctonear((exact as i128 + offset) as u128);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id("operator.near".parse().unwrap())
                .attached_deposit(attached)
                .build()
        );

        // When
        let result = contract.prepay_attestation_storage(node.clone(), 2);

        // Then
        assert_matches!(
            &result,
            Err(Error::InvalidParameters(InvalidParameters::UnexpectedDeposit {
                attached: a,
                required
            })) if *a == attached.as_yoctonear() && *required == exact
        );
        assert_eq!(contract.available_attestation_grants(node), 0);
    }

    #[test]
    fn prepay_attestation_storage__should_reject_zero_grants() {
        // Given
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let node: AccountId = "newcomer.near".parse().unwrap();
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id("operator.near".parse().unwrap())
                .attached_deposit(NearToken::from_yoctonear(0))
                .build()
        );

        // When
        let result = contract.prepay_attestation_storage(node.clone(), 0);

        // Then
        assert_matches!(
            &result,
            Err(Error::InvalidParameters(
                InvalidParameters::MalformedPayload { .. }
            ))
        );
        assert_eq!(contract.available_attestation_grants(node), 0);
    }

    /// Without this the async path would store for free while the synchronous one charged.
    #[test]
    fn resolve_verification__should_consume_one_grant_when_the_entry_is_new() {
        // Given: the setup prepays one grant for alice.near.
        let (mut contract, context) = dstack_verification_setup();
        let account_id = context.node_id.account_id.clone();
        assert_eq!(contract.available_attestation_grants(account_id.clone()), 1);

        // When
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(
            contract.available_attestation_grants(account_id),
            0,
            "storing a new entry should consume the grant"
        );
    }

    /// The callback runs a receipt later than the submission that reserved the grant, so it
    /// re-checks availability: another submission from the same account may have spent it in
    /// between. Without the re-check this would store an entry no grant paid for.
    #[test]
    fn resolve_verification__should_store_nothing_when_the_grant_was_spent_before_the_callback() {
        // Given: the grant reserved at submit time is gone by the time the callback runs.
        let (mut contract, context) = dstack_verification_setup();
        let account_id = context.node_id.account_id.clone();
        contract.available_attestation_grants.remove(&account_id);

        // When
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then: the submitter's transaction is failed from its own receipt, and nothing is stored.
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Promise(_)));
        assert!(contract.tee_state.stored_attestations.is_empty());
    }

    #[test]
    fn resolve_verification__should_store_on_verified_verdict() {
        // Given
        let (mut contract, context) = dstack_verification_setup();
        let node_id = context.node_id.clone();

        // When
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(contract.tee_state.stored_attestations.len(), 1);
        let stored = contract
            .tee_state
            .stored_attestations
            .get(&node_id.tls_public_key)
            .expect("attestation must be stored");
        assert_eq!(stored.node_id, node_id);
    }

    #[test]
    fn resolve_verification__should_refresh_launcher_for_participant() {
        // Given a launcher whose expiry was stamped earlier (STAMPED_AT_SECONDS), to be
        // resolved later (RESOLVE_AT_SECONDS) by a current participant.
        const STAMPED_AT_SECONDS: u64 = VALID_ATTESTATION_TIMESTAMP - 1_000;
        let resolve_at_seconds = VALID_ATTESTATION_TIMESTAMP;

        let (mut contract, context) = dstack_verification_setup();
        let ttl_secs = contract.config.launcher_hash_unused_ttl_seconds;
        let ttl = Duration::from_secs(ttl_secs);

        let participant: AccountId = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .participants()[0]
            .0
            .clone();

        // Stamp the launcher earlier with the config TTL so its expiry is
        // STAMPED_AT_SECONDS + ttl; a refresh on resolve (restamps to
        // RESOLVE_AT_SECONDS + ttl) is then observable.
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(STAMPED_AT_SECONDS * 1_000_000_000)
                .build()
        );
        contract.tee_state.allowed_launcher_images.add_or_refresh(
            launcher_image_hash(),
            &[image_digest()],
            ttl,
        );
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );

        // When resolve runs later with the signer set to a current participant. Predecessor
        // stays the contract account for the `#[private]` callback.
        let contract_account_id = env::current_account_id();
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(contract_account_id.clone())
                .predecessor_account_id(contract_account_id)
                .signer_account_id(participant)
                .block_timestamp(resolve_at_seconds * 1_000_000_000)
                .build()
        );
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then the launcher is refreshed by the participant: expiry restamped to
        // RESOLVE_AT_SECONDS + ttl.
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(resolve_at_seconds + ttl_secs)
        );
    }

    #[test]
    fn resolve_verification__should_not_refresh_for_non_participant() {
        // Given a launcher whose expiry was stamped earlier (STAMPED_AT_SECONDS), to be
        // resolved later (RESOLVE_AT_SECONDS) by a non-participant.
        const STAMPED_AT_SECONDS: u64 = VALID_ATTESTATION_TIMESTAMP - 1_000;
        let resolve_at_seconds = VALID_ATTESTATION_TIMESTAMP;

        let (mut contract, context) = dstack_verification_setup();
        let ttl_secs = contract.config.launcher_hash_unused_ttl_seconds;
        let ttl = Duration::from_secs(ttl_secs);

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(STAMPED_AT_SECONDS * 1_000_000_000)
                .build()
        );
        contract.tee_state.allowed_launcher_images.add_or_refresh(
            launcher_image_hash(),
            &[image_digest()],
            ttl,
        );
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );

        // When resolve runs later with a non-participant signer: the submission still stores,
        // but the launcher's expiry must not be extended.
        let non_participant: AccountId = "non-participant.near".parse().unwrap();
        let contract_account_id = env::current_account_id();
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(contract_account_id.clone())
                .predecessor_account_id(contract_account_id)
                .signer_account_id(non_participant)
                .block_timestamp(resolve_at_seconds * 1_000_000_000)
                .build()
        );
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then the launcher is not refreshed: expiry unchanged from the setup stamp.
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );
    }

    #[test]
    fn submit_participant_info__should_not_refresh_launcher_for_non_participant() {
        // Given a launcher stamped earlier (STAMPED_AT_SECONDS) with the config TTL, so its
        // expiry is STAMPED_AT_SECONDS + ttl.
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let ttl_secs = contract.config.launcher_hash_unused_ttl_seconds;
        let ttl = Duration::from_secs(ttl_secs);

        let launcher = LauncherImageHash::from([7u8; 32]);
        let mpc_hash = crate::tee::proposal::NodeImageHash::from([8u8; 32]);
        let compose = crate::tee::proposal::get_docker_compose_hash(&launcher, &mpc_hash);

        const STAMPED_AT_SECONDS: u64 = 1_000_000;
        let submit_at_seconds = STAMPED_AT_SECONDS + 1_000;

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(STAMPED_AT_SECONDS * 1_000_000_000)
                .build()
        );
        contract
            .tee_state
            .allowed_launcher_images
            .add_or_refresh(launcher, &[mpc_hash], ttl);
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );

        // When a non-participant submits a `WithConstraints` mock referencing the live
        // launcher later (submit_at_seconds > STAMPED_AT_SECONDS). The submission stores, but
        // the participant-gated refresh must not run.
        let non_participant: AccountId = "non-participant.near".parse().unwrap();
        // Storing a new entry consumes an attestation-storage grant; this test is about the
        // launcher refresh gate, so fund the submission rather than have it rejected earlier.
        contract
            .available_attestation_grants
            .insert(non_participant.clone(), 1);
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(non_participant.clone())
                .predecessor_account_id(non_participant)
                .block_timestamp(submit_at_seconds * 1_000_000_000)
                .build()
        );
        let tls_key = Ed25519PublicKey([9u8; 32]);
        let mock = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: Some(compose),
            expiry_timestamp_seconds: Some(submit_at_seconds + 1_000_000),
            expected_measurements: None,
        };
        let _ = contract
            .submit_participant_info(Attestation::Mock(mock), tls_key.clone())
            .unwrap();

        // Then the attestation is stored (so it reached the gate)...
        assert!(
            contract
                .tee_state
                .stored_attestations
                .get(&tls_key)
                .is_some()
        );
        // ...but the launcher's expiry was not extended.
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );
    }

    #[test]
    fn resolve_verification__should_return_fail_promise_and_store_nothing_on_verifier_unavailable()
    {
        // Given
        let (mut contract, context) = dstack_verification_setup();

        // When
        let result = contract.resolve_verification(context, Err(PromiseError::Failed));

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Promise(_)));
        assert!(contract.tee_state.stored_attestations.is_empty());
    }

    #[test]
    #[should_panic(expected = "Caller must be an attested participant")]
    fn test_attested_but_not_participant_panics() {
        let (mut contract, participants, _first_participant_id) = setup_tee_test_contract(3, 2);

        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        let outsider_id: AccountId = "outsider.near".parse().unwrap();

        let fake_tls_pk = bogus_ed25519_near_public_key(); // unique TLS key for outsider
        let dto_public_key = dtos::Ed25519PublicKey::try_from(&fake_tls_pk).unwrap();

        let valid_attestation = Attestation::Mock(MockAttestation::Valid);

        // A new entry consumes a grant; stand in for the operator's prepayment.
        contract
            .available_attestation_grants
            .insert(outsider_id.clone(), 1);

        // use outsider account to call submit_participant_info
        let ctx = VMContextBuilder::new()
            .signer_account_id(outsider_id.clone())
            .predecessor_account_id(outsider_id.clone())
            .build();
        testing_env!(ctx);

        let _ = contract
            .submit_participant_info(valid_attestation, dto_public_key)
            .expect("Outsider attestation submission should succeed");

        contract.assert_caller_is_attested_participant_and_protocol_active();
    }

    /// Tests that [`MpcContract::verify_tee`] triggers resharing and kicks out a participant
    /// when their attestation is expired.
    ///
    /// Verifies the behavior when:
    /// 1. [`MpcContract::verify_tee`] returns [`TeeValidationResult::Partial`] (some attestations
    ///    expired/invalid)
    /// 2. The remaining participants meet threshold requirements
    /// 3. The contract transitions to [`ProtocolContractState::Resharing`] state
    /// 4. The participant with expired attestation is excluded from the new parameters
    #[test]
    fn test_verify_tee_triggers_resharing_and_kickout_on_expired_attestation() {
        const PARTICIPANT_COUNT: usize = 3;
        const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
        const TEE_UPGRADE_DURATION: Duration = Duration::MAX;

        let participants = gen_participants(PARTICIPANT_COUNT);
        let parameters =
            GovernanceThresholdParameters::new(participants.clone(), GovernanceThreshold::new(2))
                .unwrap();

        // Set up contract in Running state
        let domain_id = DomainId::default();
        let domains = vec![DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }];
        let (pk, _) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let key_for_domain = KeyForDomain {
            domain_id,
            key: pk.try_into().unwrap(),
            attempt: AttemptId::new(),
        };
        let keyset = Keyset::new(EpochId::new(0), vec![key_for_domain.clone()]);

        let mut contract = MpcContract::init_running(
            domains.clone(),
            1,
            (&keyset).into_dto_type(),
            (&parameters).into_dto_type(),
            bogus_tee_verifier_account_id(),
            None,
        )
        .unwrap();

        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));

        // Get participant info for the target (last participant)
        let participant_list: Vec<_> = participants.participants().to_vec();
        let (target_account_id, _, target_participant_info) = &participant_list[2];

        // Replace the target's attestation with an expired one
        let node_id = create_node_id(target_account_id, &target_participant_info.tls_public_key);
        let expiring_attestation = MpcMockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(ATTESTATION_EXPIRY_SECONDS),
            expected_measurements: None,
        };
        contract
            .tee_state
            .verify_and_store_mock(node_id, expiring_attestation, TEE_UPGRADE_DURATION)
            .expect("mock attestation is not yet expired and valid");

        // Capture the running state before verify_tee for comparison
        let ProtocolContractState::Running(running_state_before) = &contract.protocol_state else {
            panic!("expected Running state");
        };
        let running_state_before = running_state_before.clone();

        // Set time to exact expiry boundary
        let (first_account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(first_account_id.clone())
                .predecessor_account_id(first_account_id.clone())
                .block_timestamp(ATTESTATION_EXPIRY_SECONDS * 1_000_000_000) // nanoseconds
                .build()
        );

        // Call verify_tee - should trigger resharing
        let result = contract.verify_tee();
        assert_matches!(
            result,
            Ok(true),
            "verify_tee should return Ok(true) when threshold is met"
        );

        // Verify contract transitioned to Resharing state
        let ProtocolContractState::Resharing(resharing_state) = &contract.protocol_state else {
            panic!(
                "expected Resharing state, got {:?}",
                contract.protocol_state
            );
        };

        // Build expected participants: exclude the target (participant 2) who has expired attestation
        let expected_participants = Participants::init(
            ParticipantId(PARTICIPANT_COUNT as u32),
            participant_list[0..2]
                .iter()
                .map(|(acc, id, info)| (acc.clone(), *id, info.clone()))
                .collect(),
        );
        let expected_params =
            GovernanceThresholdParameters::new(expected_participants, parameters.threshold())
                .unwrap();

        let expected_resharing_state = ResharingContractState {
            previous_running_state: running_state_before,
            reshared_keys: Vec::new(),
            resharing_key: KeyEvent::new(
                keyset.epoch_id.next(),
                domains[0].clone(),
                expected_params,
            ),
            cancellation_requests: HashSet::new(),
            per_domain_thresholds: BTreeMap::new(),
        };

        assert_eq!(*resharing_state, expected_resharing_state);
    }

    /// Tests that [`MpcContract::verify_tee`] refuses to reshare when a TEE
    /// kickout would leave fewer participants than the threshold relation requires.
    /// The contract stays Running and stops accepting requests.
    #[test]
    fn verify_tee__should_refuse_kickout_when_remaining_breaks_threshold_relation() {
        const PARTICIPANT_COUNT: usize = 5;
        const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
        const TEE_UPGRADE_DURATION: Duration = Duration::MAX;

        // Given: 5 participants, GovernanceThreshold 5, and one domain whose
        // reconstruction threshold is 5 (every participant is needed to sign). Dropping
        // to 4 participants would leave the GovernanceThreshold above the participant
        // count, breaking the threshold relation.
        let participants = gen_participants(PARTICIPANT_COUNT);
        let parameters = GovernanceThresholdParameters::new(
            participants.clone(),
            GovernanceThreshold::new(
                u64::try_from(PARTICIPANT_COUNT).expect("participant count fits in u64"),
            ),
        )
        .unwrap();
        let domain_id = DomainId::default();
        let domains = vec![DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(5),
            purpose: DomainPurpose::Sign,
        }];
        let (pk, _) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let keyset = Keyset::new(
            EpochId::new(0),
            vec![KeyForDomain {
                domain_id,
                key: pk.try_into().unwrap(),
                attempt: AttemptId::new(),
            }],
        );
        let mut contract = MpcContract::init_running(
            domains,
            1,
            (&keyset).into_dto_type(),
            (&parameters).into_dto_type(),
            bogus_tee_verifier_account_id(),
            None,
        )
        .unwrap();

        // Expire the last participant's attestation so a kickout drops the set to 4.
        let participant_list: Vec<_> = participants.participants().to_vec();
        let (target_account_id, _, target_participant_info) =
            &participant_list[PARTICIPANT_COUNT - 1];
        let node_id = create_node_id(target_account_id, &target_participant_info.tls_public_key);
        let expiring_attestation = MpcMockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(ATTESTATION_EXPIRY_SECONDS),
            expected_measurements: None,
        };
        contract
            .tee_state
            .verify_and_store_mock(node_id, expiring_attestation, TEE_UPGRADE_DURATION)
            .expect("mock attestation is not yet expired and valid");

        let (first_account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(first_account_id.clone())
                .predecessor_account_id(first_account_id.clone())
                .block_timestamp(ATTESTATION_EXPIRY_SECONDS * 1_000_000_000) // nanoseconds
                .build()
        );

        // When
        let result = contract.verify_tee();

        // Then: with only 4 surviving participants the GovernanceThreshold of 5 would
        // exceed the participant count, breaking the threshold relation, so verify_tee
        // refuses to reshare, stays Running, and stops accepting requests.
        assert_matches!(result, Ok(false));
        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));
        assert!(!contract.accept_requests);
    }

    const MAX_HASH: [u8; 32] = [0xff; 32];

    /// Charged storage of the largest attestation entry the contract can store, in bytes:
    /// a 64-byte account id (NEAR's cap) plus fixed-width keys and the largest
    /// [`VerifiedAttestation`] variant, including the
    /// [`IterableMap`](near_sdk::store::IterableMap) record overhead.
    const WORST_CASE_ENTRY_BYTES: u64 = 604;

    /// Ceiling on one entry's storage cost at today's price, with headroom over
    /// [`WORST_CASE_ENTRY_BYTES`] for storage-price changes.
    const WORST_CASE_ENTRY_COST_CEILING: NearToken = NearToken::from_millinear(10);

    fn worst_case_dstack_attestation() -> VerifiedAttestation {
        VerifiedAttestation::Dstack(ValidatedDstackAttestation {
            mpc_image_hash: MAX_HASH.into(),
            launcher_compose_hash: MAX_HASH.into(),
            expiry_timestamp_seconds: u64::MAX,
            measurements: default_measurements()[0],
        })
    }

    fn worst_case_mock_attestation() -> VerifiedAttestation {
        VerifiedAttestation::Mock(MpcMockAttestation::WithConstraints {
            mpc_docker_image_hash: Some(MAX_HASH.into()),
            launcher_docker_compose_hash: Some(MAX_HASH.into()),
            expiry_timestamp_seconds: Some(u64::MAX),
            expected_measurements: Some(default_measurements()[0]),
        })
    }

    /// Storage the contract pays for one stored attestation entry, measured the way the runtime
    /// charges it. NEAR caps an account id at 64 bytes; every other [`NodeId`] field is fixed-size,
    /// so this is the worst case for the given attestation variant.
    fn measure_stored_entry_bytes(verified_attestation: VerifiedAttestation) -> u64 {
        testing_env!(VMContextBuilder::new().build());
        let node_id = create_node_id(
            &"a".repeat(64).parse().unwrap(),
            &bogus_ed25519_public_key(),
        );

        let mut tee_state = TeeState::default();
        let before = env::storage_usage();
        tee_state.stored_attestations.insert(
            node_id.tls_public_key.clone(),
            NodeAttestation {
                node_id,
                verified_attestation,
            },
        );
        tee_state.stored_attestations.flush();

        env::storage_usage() - before
    }

    fn measure_grant_row_bytes() -> u64 {
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        testing_env!(VMContextBuilder::new().build());
        let account: AccountId = "a".repeat(64).parse().unwrap();

        let before = env::storage_usage();
        contract.available_attestation_grants.insert(account, 1);
        contract.available_attestation_grants.flush();

        env::storage_usage() - before
    }

    /// Pins the exact stored size of the largest variant of each attestation kind.
    ///
    /// Do not update these numbers just to make a failing case pass. The contract funds every
    /// entry from its own balance, so a size change alters what the contract pays per node, and
    /// everything derived from it must be revisited in the same change — today
    /// [`WORST_CASE_ENTRY_BYTES`] and [`WORST_CASE_ENTRY_COST_CEILING`].
    ///
    /// The prepaid-storage fee is sized from these numbers.
    #[rstest]
    #[case::dstack(599, worst_case_dstack_attestation())]
    #[case::mock(604, worst_case_mock_attestation())]
    fn stored_attestation_entry__should_have_the_pinned_size(
        #[case] expected_bytes: u64,
        #[case] verified_attestation: VerifiedAttestation,
    ) {
        // Given / When
        let bytes_stored = measure_stored_entry_bytes(verified_attestation);

        // Then
        assert_eq!(
            bytes_stored, expected_bytes,
            "stored entry size changed; see this test's doc comment before updating the number"
        );
        assert!(
            bytes_stored <= WORST_CASE_ENTRY_BYTES,
            "entry ({bytes_stored} bytes) exceeds the pinned worst case \
             ({WORST_CASE_ENTRY_BYTES} bytes)"
        );
    }

    /// The fee covers the worst-case entry plus the grants row, and is held to twice that, so
    /// growth is caught while there is still room rather than once the fee is already breached.
    /// A failure here is a prompt to re-price, not a broken test.
    ///
    /// Does not guard a real storage re-pricing: [`env::storage_byte_cost`] is a near-sdk
    /// constant, not a protocol read.
    ///
    /// TODO(#4123): a fee voted below the floor is not caught here either.
    #[test]
    fn attestation_storage_fee__should_keep_double_the_floor() {
        // Given
        const BUFFER: u128 = 2;
        let worst_case_entry_bytes = measure_stored_entry_bytes(worst_case_mock_attestation())
            .max(measure_stored_entry_bytes(worst_case_dstack_attestation()));
        let floor_bytes = worst_case_entry_bytes + measure_grant_row_bytes();

        // When
        let floor = env::storage_byte_cost().saturating_mul(u128::from(floor_bytes));
        let fee = NearToken::from_millinear(u128::from(
            Config::default().attestation_storage_fee_millinear,
        ));

        // Then
        assert!(
            floor.saturating_mul(BUFFER) <= fee,
            "attestation storage fee ({fee}) must be at least {BUFFER}x the floor \
             ({floor_bytes} bytes, {floor}) at today's storage price"
        );
    }

    #[rstest]
    #[case::dstack(worst_case_dstack_attestation())]
    #[case::mock(worst_case_mock_attestation())]
    fn stored_attestation_entry__should_stay_under_the_cost_ceiling(
        #[case] verified_attestation: VerifiedAttestation,
    ) {
        // Given / When
        let bytes_grown = measure_stored_entry_bytes(verified_attestation);
        let cost = env::storage_byte_cost().saturating_mul(u128::from(bytes_grown));

        // Then
        assert!(
            cost <= WORST_CASE_ENTRY_COST_CEILING,
            "worst-case entry cost ({bytes_grown} bytes, {cost}) must stay under \
             {WORST_CASE_ENTRY_COST_CEILING} at today's storage price"
        );
    }
}
