//! Confidential key derivation functionality

use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{Error, InvalidState, TeeError};
use crate::primitives::ckd::{CKDRequest, app_public_key_check, ckd_output_check};
use crate::primitives::signature::YieldIndex;
use crate::{MpcContract, MpcContractExt, pending_requests};
use dtos::{DomainId, DomainPurpose};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{self as dtos, CKDRequestArgs, CKDResponse};
use near_sdk::{CryptoHash, Gas, NearToken, Promise, PromiseError, PromiseOrValue, env, log, near};

#[near]
impl MpcContract {
    fn add_ckd_request(&mut self, request: CKDRequest, data_id: CryptoHash) {
        pending_requests::push_pending_yield(&mut self.pending_ckd_requests, request, data_id);
    }

    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each ckd request.
    ///
    /// Note: identity points are accepted in
    /// [`AppPublicKeyPV`](near_mpc_contract_interface::types::CKDAppPublicKey::AppPublicKeyPV)
    /// to support use cases
    /// where the derived key is intentionally public (no encryption).
    #[handle_result]
    #[payable]
    pub fn request_app_private_key(&mut self, request: CKDRequestArgs) {
        log!(
            "request_app_private_key: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );

        let domain_id: DomainId = request.domain_id;
        let (_, predecessor) = self.check_request_preconditions(
            domain_id,
            DomainPurpose::CKD,
            Gas::from_tgas(self.config.ckd_call_gas_attachment_requirement_tera_gas),
            MINIMUM_CKD_REQUEST_DEPOSIT,
        );

        match &request.app_public_key {
            dtos::CKDAppPublicKey::AppPublicKey(_) => {}
            dtos::CKDAppPublicKey::AppPublicKeyPV(pk) => {
                if !app_public_key_check(pk) {
                    env::panic_str("app public key check failed")
                }
            }
        }

        let request = CKDRequest::new(
            request.app_public_key,
            domain_id,
            &predecessor,
            &request.derivation_path,
        );

        let callback_gas = Gas::from_tgas(
            self.config
                .return_ck_and_clean_state_on_success_call_tera_gas,
        );

        let callback_args = serde_json::to_vec(&(&request,)).unwrap();
        self.enqueue_yield_request(
            method_names::RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS,
            callback_args,
            callback_gas,
            move |this, id| this.add_ckd_request(request, id),
        );
    }

    #[handle_result]
    pub fn respond_ckd(&mut self, request: CKDRequest, response: CKDResponse) -> Result<(), Error> {
        let signer = Self::assert_caller_is_signer();
        log!("respond_ckd: signer={}, request={:?}", &signer, &request);

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        self.assert_caller_is_attested_participant_and_protocol_active();

        let PublicKeyExtended::Bls12381 {
            public_key: dtos::PublicKey::Bls12381(public_key),
        } = self.public_key_extended(request.domain_id)?
        else {
            env::panic_str("Domain is not compatible with CKD (expected Bls12381 curve)");
        };

        match &request.app_public_key {
            dtos::CKDAppPublicKey::AppPublicKey(_) => {}
            dtos::CKDAppPublicKey::AppPublicKeyPV(app_pk) => {
                if !ckd_output_check(&request.app_id, &response, app_pk, &public_key) {
                    env::panic_str("CKD output check failed");
                }
            }
        }

        pending_requests::resolve_yields_for(
            &mut self.pending_ckd_requests,
            &request,
            serde_json::to_vec(&response).unwrap(),
        )
    }

    /// Presence check for a pending CKD request, exposed as a view call.
    ///
    /// See [`Self::get_pending_request`] for the contract: the returned [`YieldIndex`]
    /// is an arbitrary representative of a fan-out queue, not "the" yield. Only the
    /// `Some`/`None` distinction is meaningful.
    pub fn get_pending_ckd_request(&self, request: &CKDRequest) -> Option<YieldIndex> {
        self.pending_ckd_requests
            .get(request)
            .and_then(|q| q.first().cloned())
    }

    /// Yield-resume callback for a single queued CKD request.
    ///
    /// On success, returns the confidential key to the original caller. On timeout,
    /// pops this yield's slot (the head of the FIFO fan-out queue) from the
    /// pending-request map and fires `fail_on_timeout` to fail the original
    /// transaction. Sibling yields queued under the same request key remain pending
    /// and are cleaned up by their own timeouts (or drained together by a subsequent
    /// `respond_ckd`).
    #[private]
    pub fn return_ck_and_clean_state_on_success(
        &mut self,
        request: CKDRequest,
        #[callback_result] ck: Result<CKDResponse, PromiseError>,
    ) -> PromiseOrValue<CKDResponse> {
        match ck {
            Ok(ck) => PromiseOrValue::Value(ck),
            Err(_) => {
                pending_requests::pop_oldest_pending_yield(
                    &mut self.pending_ckd_requests,
                    &request,
                );
                let fail_on_timeout_gas = Gas::from_tgas(self.config.fail_on_timeout_tera_gas);
                let promise = Promise::new(env::current_account_id()).function_call(
                    method_names::FAIL_ON_TIMEOUT.to_string(),
                    vec![],
                    NearToken::from_near(0),
                    fail_on_timeout_gas,
                );
                near_sdk::PromiseOrValue::Promise(promise.as_return())
            }
        }
    }
}

/// Minimum deposit required for CKD requests
pub(crate) const MINIMUM_CKD_REQUEST_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{
        SharedSecretKey, basic_setup, basic_setup_with_protocol, submit_valid_attestations,
        with_active_participant_and_attested_context,
    };
    use crate::primitives::test_utils::bogus_ed25519_near_public_key;
    use crate::state::ProtocolContractState;
    use dtos::{Attestation, Curve, MockAttestation, Protocol};
    use elliptic_curve::{Field as _, Group};
    use k256::{self, elliptic_curve};
    use near_mpc_contract_interface::types::CKDAppPublicKey;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, testing_env};
    use rand::SeedableRng;
    use rand::rngs::OsRng;
    use rand_core::CryptoRngCore;
    use rstest::rstest;
    use std::panic;
    use threshold_signatures::confidential_key_derivation as ckd;

    pub fn new_ckd_pv_app_pk(
        rng: &mut impl CryptoRngCore,
    ) -> (ckd::Scalar, dtos::CKDAppPublicKeyPV) {
        let scalar = ckd::Scalar::random(rng);
        let pk2 = ckd::ElementG2::generator() * scalar;
        let pk1 = ckd::ElementG1::generator() * scalar;

        let pk2 = dtos::Bls12381G2PublicKey::from(&pk2);
        let pk1 = dtos::Bls12381G1PublicKey::from(&pk1);

        (scalar, dtos::CKDAppPublicKeyPV { pk1, pk2 })
    }

    pub fn compute_ckd_pv_response(msk: &ckd::Scalar, request: &CKDRequest) -> CKDResponse {
        let public_key = ckd::ElementG2::generator() * msk;
        let public_key = ckd::VerifyingKey::new(public_key);
        let app_pk = ckd::ElementG1::try_from(request.app_public_key.g1_public_key()).unwrap();
        let big_s = ckd::hash_app_id_with_pk(&public_key, request.app_id.as_ref()) * msk;
        let y = ckd::Scalar::random(OsRng);
        let big_y = ckd::ElementG1::generator() * y;
        let big_c = big_s + app_pk * y;

        CKDResponse {
            big_y: (&big_y).into(),
            big_c: (&big_c).into(),
        }
    }

    #[test]
    fn respond_ckd__should_succeed_when_response_is_valid_and_request_exists() {
        let (context, mut contract, _secret_key) = basic_setup(Curve::Bls12381, &mut OsRng);
        let app_public_key: dtos::Bls12381G1PublicKey =
            "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                .parse()
                .unwrap();
        let request = CKDRequestArgs {
            derivation_path: "".to_string(),
            app_public_key: CKDAppPublicKey::AppPublicKey(app_public_key.clone()),
            domain_id: dtos::DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            CKDAppPublicKey::AppPublicKey(app_public_key),
            request.domain_id,
            &context.predecessor_account_id,
            &request.derivation_path,
        );
        contract.request_app_private_key(request);
        contract.get_pending_ckd_request(&ckd_request).unwrap();

        let response = CKDResponse {
            big_y: dtos::Bls12381G1PublicKey([1u8; 48]),
            big_c: dtos::Bls12381G1PublicKey([2u8; 48]),
        };

        with_active_participant_and_attested_context(&contract);

        match contract.respond_ckd(ckd_request.clone(), response.clone()) {
            Ok(_) => {
                contract
                    .return_ck_and_clean_state_on_success(ckd_request.clone(), Ok(response))
                    .detach();

                assert!(contract.get_pending_ckd_request(&ckd_request).is_none(),);
            }
            Err(_) => panic!("respond_ckd should not fail"),
        }
    }

    #[test]
    fn respond_ckd_pv__should_succeed_when_response_is_valid_and_request_exists() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) = basic_setup(Curve::Bls12381, &mut rng);
        let SharedSecretKey::Bls12381(secret_key) = secret_key else {
            unreachable!();
        };
        let (_, app_public_key) = new_ckd_pv_app_pk(&mut rng);
        let app_public_key = CKDAppPublicKey::AppPublicKeyPV(app_public_key);
        let derivation_path = "my derivation path".to_string();
        let request = CKDRequestArgs {
            derivation_path,
            app_public_key: app_public_key.clone(),
            domain_id: dtos::DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            app_public_key,
            request.domain_id,
            &context.predecessor_account_id,
            &request.derivation_path,
        );
        contract.request_app_private_key(request);
        contract.get_pending_ckd_request(&ckd_request).unwrap();

        let response = compute_ckd_pv_response(&secret_key, &ckd_request);

        with_active_participant_and_attested_context(&contract);

        match contract.respond_ckd(ckd_request.clone(), response.clone()) {
            Ok(_) => {
                contract
                    .return_ck_and_clean_state_on_success(ckd_request.clone(), Ok(response))
                    .detach();

                assert!(contract.get_pending_ckd_request(&ckd_request).is_none(),);
            }
            Err(_) => panic!("respond_ckd should not fail"),
        }
    }

    #[test]
    #[should_panic(expected = "app public key check failed")]
    fn request_ckd_pv__should_reject_mismatched_app_public_key() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _secret_key) = basic_setup(Curve::Bls12381, &mut rng);

        // Generate pk1 and pk2 from different scalars so the pairing check fails
        let scalar1 = ckd::Scalar::random(&mut rng);
        let scalar2 = ckd::Scalar::random(&mut rng);
        let pk1 = dtos::Bls12381G1PublicKey::from(&(ckd::ElementG1::generator() * scalar1));
        let pk2 = dtos::Bls12381G2PublicKey::from(&(ckd::ElementG2::generator() * scalar2));

        let request = CKDRequestArgs {
            derivation_path: "test".to_string(),
            app_public_key: CKDAppPublicKey::AppPublicKeyPV(dtos::CKDAppPublicKeyPV { pk1, pk2 }),
            domain_id: dtos::DomainId::default(),
        };
        contract.request_app_private_key(request);
    }

    #[test]
    #[should_panic(expected = "CKD output check failed")]
    fn respond_ckd_pv__should_reject_invalid_response() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) = basic_setup(Curve::Bls12381, &mut rng);
        let SharedSecretKey::Bls12381(secret_key) = secret_key else {
            unreachable!();
        };

        let (_, app_public_key) = new_ckd_pv_app_pk(&mut rng);
        let app_public_key = CKDAppPublicKey::AppPublicKeyPV(app_public_key);
        let request = CKDRequestArgs {
            derivation_path: "test".to_string(),
            app_public_key: app_public_key.clone(),
            domain_id: dtos::DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            app_public_key,
            request.domain_id,
            &context.predecessor_account_id,
            &request.derivation_path,
        );
        contract.request_app_private_key(request);

        // Compute a valid response then tamper with big_c
        let mut response = compute_ckd_pv_response(&secret_key, &ckd_request);
        response.big_c = dtos::Bls12381G1PublicKey::from(
            &(ckd::ElementG1::generator() * ckd::Scalar::random(&mut rng)),
        );

        with_active_participant_and_attested_context(&contract);
        let _ = contract.respond_ckd(ckd_request, response);
    }

    #[test]
    fn test_ckd_timeout() {
        let (context, mut contract, _secret_key) = basic_setup(Curve::Bls12381, &mut OsRng);
        let app_public_key: dtos::Bls12381G1PublicKey =
            "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                .parse()
                .unwrap();
        let request = CKDRequestArgs {
            derivation_path: "".to_string(),
            app_public_key: CKDAppPublicKey::AppPublicKey(app_public_key.clone()),
            domain_id: dtos::DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            CKDAppPublicKey::AppPublicKey(app_public_key),
            request.domain_id,
            &context.predecessor_account_id,
            &request.derivation_path,
        );
        contract.request_app_private_key(request);
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(
            contract.return_ck_and_clean_state_on_success(
                ckd_request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(contract.get_pending_ckd_request(&ckd_request).is_none());
    }

    #[rstest]
    #[case(DomainPurpose::Sign)]
    #[case(DomainPurpose::ForeignTx)]
    #[should_panic(expected = "this method requires CKD")]
    fn ckd__should_reject_non_ckd_domain(#[case] purpose: DomainPurpose) {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, purpose, &mut rng);

        // When
        contract.request_app_private_key(CKDRequestArgs {
            domain_id: dtos::DomainId::default(),
            derivation_path: "test".to_string(),
            app_public_key: CKDAppPublicKey::AppPublicKey(dtos::Bls12381G1PublicKey::from(
                [0u8; 48],
            )),
        });
    }

    #[test]
    fn test_respond_ckd_fails_for_attested_non_participant() {
        // --- Step 1: Setup standard contract with Bls domain and threshold=2 ---
        let (context, mut contract, _secret_key) = basic_setup(Curve::Bls12381, &mut OsRng);

        // Submit valid attestations for all participants (so contract is in Running state)
        // 2. Extract participants list (we have 4 by default)
        let participants = match &contract.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants().clone(),
            _ => panic!("Contract should be in Running state"),
        };

        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        // --- Step 2: Create a valid CKD request by a legitimate participant ---
        let app_public_key: dtos::Bls12381G1PublicKey =
            "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                .parse()
                .unwrap();
        let request = CKDRequestArgs {
            derivation_path: "".to_string(),
            app_public_key: CKDAppPublicKey::AppPublicKey(app_public_key.clone()),
            domain_id: dtos::DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            CKDAppPublicKey::AppPublicKey(app_public_key),
            request.domain_id,
            &context.predecessor_account_id.clone(),
            &request.derivation_path,
        );

        // Legit participant makes the CKD request
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(context.predecessor_account_id.clone())
                .predecessor_account_id(context.predecessor_account_id.clone())
                .attached_deposit(NearToken::from_near(1))
                .build()
        );
        contract.request_app_private_key(request);
        assert!(contract.get_pending_ckd_request(&ckd_request).is_some());

        // --- Step 3: Attested outsider (not a participant) joins ---
        let outsider_id: AccountId = "outsider.near".parse().unwrap();
        let tls_key = bogus_ed25519_near_public_key();
        let dto_public_key = dtos::Ed25519PublicKey::try_from(&tls_key).unwrap();

        // A new entry consumes a grant; stand in for the operator's prepayment.
        contract
            .available_attestation_grants
            .insert(outsider_id.clone(), 1);

        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(outsider_id.clone())
                .predecessor_account_id(outsider_id.clone())
                .build()
        );

        let _ = contract
            .submit_participant_info(Attestation::Mock(MockAttestation::Valid), dto_public_key)
            .unwrap();

        // --- Step 4: Verify that a participant can still respond successfully ---
        with_active_participant_and_attested_context(&contract); // sets env to a real attested participant

        let valid_response = CKDResponse {
            big_y: dtos::Bls12381G1PublicKey([1u8; 48]),
            big_c: dtos::Bls12381G1PublicKey([2u8; 48]),
        };

        // This should succeed (attested participant)
        contract
            .respond_ckd(ckd_request.clone(), valid_response.clone())
            .expect("Participant should be allowed to respond_ckd");

        // --- Step 5: Now switch to attested outsider and verify it panics ---
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(outsider_id.clone())
                .predecessor_account_id(outsider_id.clone())
                .attached_deposit(NearToken::from_near(1))
                .build()
        );

        let outsider_response = CKDResponse {
            big_y: dtos::Bls12381G1PublicKey([3u8; 48]),
            big_c: dtos::Bls12381G1PublicKey([4u8; 48]),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract
                .respond_ckd(ckd_request.clone(), outsider_response)
                .unwrap();
        }));

        assert!(
            result.is_err(),
            "Expected panic from attested non-participant"
        );

        if let Err(err) = result {
            if let Some(msg) = err.downcast_ref::<&str>() {
                assert!(
                    msg.contains("Caller must be an attested participant"),
                    "Unexpected panic message: {}",
                    msg
                );
            } else if let Some(msg) = err.downcast_ref::<String>() {
                assert!(
                    msg.contains("Caller must be an attested participant"),
                    "Unexpected panic message: {}",
                    msg
                );
            } else {
                panic!("Unexpected panic payload type");
            }
        }
    }
}
