//! Signature request entrypoints: submitting a `sign` request, the node's `respond`,
//! and the yield-resume callback that returns the signature to the original caller.

use crate::crypto_shared::derive_key_secp256k1;
use crate::crypto_shared::kdf::derive_public_key_edwards_point_ed25519;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{Error, InvalidState, RespondError, TeeError};
use crate::{MpcContract, MpcContractExt, pending_requests};
use k256::elliptic_curve::PrimeField;
use near_mpc_contract_interface::deposits::SIGN_DEPOSIT_YOCTONEAR;
use near_mpc_contract_interface::{method_names, types as dtos};
use near_sdk::{CryptoHash, Gas, NearToken, Promise, PromiseError, PromiseOrValue, env, log, near};

#[near]
impl MpcContract {
    fn add_signature_request(&mut self, request: dtos::SignatureRequest, data_id: CryptoHash) {
        pending_requests::push_pending_yield(
            &mut self.pending_signature_requests,
            request,
            data_id,
        );
    }

    /// `key_version` must be less than or equal to the value at `latest_key_version`
    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each signature request.
    #[handle_result]
    #[payable]
    pub fn sign(&mut self, request: dtos::SignRequestArgs) {
        log!(
            "sign: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );

        let (domain_config, predecessor) = self.check_request_preconditions(
            request.domain_id,
            dtos::DomainPurpose::Sign,
            Gas::from_tgas(self.config.sign_call_gas_attachment_requirement_tera_gas),
            NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
        );

        // ensure the signer sent a valid signature request
        // It's important we fail here because the MPC nodes will fail in an identical way.
        // This allows users to get the error message
        match domain_config.protocol {
            dtos::Protocol::CaitSith | dtos::Protocol::DamgardEtAl => {
                let hash = *request.payload.as_ecdsa().expect("Payload is not Ecdsa");
                k256::Scalar::from_repr(hash.into())
                    .into_option()
                    .expect("Ecdsa payload cannot be converted to Scalar");
            }
            dtos::Protocol::Frost => {
                request.payload.as_eddsa().expect("Payload is not EdDSA");
            }
            dtos::Protocol::ConfidentialKeyDerivation => {
                env::panic_str(
                    "ConfidentialKeyDerivation is not supported for signature responses",
                );
            }
        }

        let request = dtos::SignatureRequest::new(
            request.domain_id,
            request.payload,
            &predecessor,
            &request.path,
        );

        let callback_gas = Gas::from_tgas(
            self.config
                .return_signature_and_clean_state_on_success_call_tera_gas,
        );

        let callback_args = serde_json::to_vec(&(&request,)).unwrap();
        self.enqueue_yield_request(
            method_names::RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS,
            callback_args,
            callback_gas,
            move |this, id| this.add_signature_request(request, id),
        );
    }

    #[handle_result]
    pub fn respond(
        &mut self,
        request: dtos::SignatureRequest,
        response: dtos::SignatureResponse,
    ) -> Result<(), Error> {
        let signer = Self::assert_caller_is_signer();

        log!("respond: signer={}, request={:?}", &signer, &request);

        self.assert_caller_is_attested_participant_and_protocol_active();

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        let domain = request.domain_id;
        let public_key = self.public_key_extended(domain)?;

        let signature_is_valid = match (&response, public_key) {
            (
                dtos::SignatureResponse::Secp256k1(signature_response),
                PublicKeyExtended::Secp256k1 { near_public_key },
            ) => {
                // generate the expected public key
                let affine = *k256::PublicKey::try_from(&near_public_key)
                    .expect("stored key is always valid")
                    .as_affine();
                let expected_public_key =
                    derive_key_secp256k1(&affine, &request.tweak).map_err(RespondError::from)?;

                let payload_hash = request.payload.as_ecdsa().expect("Payload is not ECDSA");

                // Check the signature is correct
                near_mpc_signature_verifier::verify_ecdsa_signature(
                    signature_response,
                    payload_hash,
                    &expected_public_key,
                )
                .is_ok()
            }
            (
                dtos::SignatureResponse::Ed25519 { signature },
                PublicKeyExtended::Ed25519 {
                    edwards_point: public_key_edwards_point,
                    ..
                },
            ) => {
                let derived_public_key_edwards_point = derive_public_key_edwards_point_ed25519(
                    &public_key_edwards_point,
                    &request.tweak,
                );
                let derived_public_key_32_bytes =
                    dtos::Ed25519PublicKey::from(derived_public_key_edwards_point.compress());

                let message = request.payload.as_eddsa().expect("Payload is not EdDSA");

                near_mpc_signature_verifier::verify_eddsa_signature(
                    signature,
                    message,
                    &derived_public_key_32_bytes,
                )
                .is_ok()
            }
            (signature_response, public_key_requested) => {
                return Err(RespondError::SignatureSchemeMismatch {
                    mpc_scheme: Box::new(signature_response.clone()),
                    user_scheme: Box::new(public_key_requested),
                }
                .into());
            }
        };

        if !signature_is_valid {
            return Err(RespondError::InvalidSignature.into());
        }

        pending_requests::resolve_yields_for(
            &mut self.pending_signature_requests,
            &request,
            serde_json::to_vec(&response).unwrap(),
        )
    }

    /// Presence check for a pending signature request, exposed as a view call.
    ///
    /// **The returned [`dtos::YieldIndex`] is an arbitrary representative, not "the" yield
    /// for this request.** Since the duplicate-request fan-out feature (PR #3187),
    /// a single request key can have N queued yields; this method returns the head of the
    /// queue. Callers that need to act on the full set are wrong to use this. The
    /// only correct interpretation is presence: `Some(_)` vs `None`.
    ///
    /// The `Option<dtos::YieldIndex>` shape is retained for JSON wire compatibility with
    /// out-of-tree consumers; the in-tree caller (`tx_sender::observe_tx_result`)
    /// only matches on presence. Prefer a `bool`-shaped accessor if one is added.
    pub fn get_pending_request(
        &self,
        request: &dtos::SignatureRequest,
    ) -> Option<dtos::YieldIndex> {
        self.pending_signature_requests
            .get(request)
            .and_then(|q| q.first().cloned())
    }

    /// Yield-resume callback for a single queued `sign` request.
    ///
    /// On success, returns the signature to the original caller. On timeout, pops this
    /// yield's slot (the head of the FIFO fan-out queue) from the pending-request map
    /// and fires `fail_on_timeout` to fail the original transaction. Sibling yields
    /// queued under the same request key remain pending and are cleaned up by their
    /// own timeouts (or drained together by a subsequent `respond`).
    #[private]
    pub fn return_signature_and_clean_state_on_success(
        &mut self,
        request: dtos::SignatureRequest,
        #[callback_result] signature: Result<dtos::SignatureResponse, PromiseError>,
    ) -> PromiseOrValue<dtos::SignatureResponse> {
        match signature {
            Ok(signature) => PromiseOrValue::Value(signature),
            Err(_) => {
                pending_requests::pop_oldest_pending_yield(
                    &mut self.pending_signature_requests,
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

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{
        SharedSecretKey, basic_setup, basic_setup_with_protocol,
        with_active_participant_and_attested_context,
    };
    use crate::pending_requests::MAX_PENDING_REQUEST_FAN_OUT;
    use assert_matches::assert_matches;
    use dtos::{Curve, DomainId, Payload, Tweak};
    use k256::ecdsa::SigningKey;
    use k256::{Secp256k1, elliptic_curve};
    use near_mpc_contract_interface::types::kdf::derive_tweak;
    use near_sdk::AccountId;
    use rand::rngs::OsRng;
    use rand::{RngCore, SeedableRng};
    use rstest::rstest;
    use std::panic;

    pub fn derive_secret_key(secret_key: &k256::SecretKey, tweak: &Tweak) -> k256::SecretKey {
        let tweak = k256::Scalar::from_repr(tweak.as_bytes().into()).unwrap();
        k256::SecretKey::new((tweak + secret_key.to_nonzero_scalar().as_ref()).into())
    }

    /// Builds the valid secp256k1 signature for `payload` under the domain key derived
    /// from `(predecessor, path)`. Shared between `test_signature_common` and
    /// `sign__should_queue_duplicate_requests_and_drain_all_on_respond` because both
    /// need an honestly-produced response to feed into `respond`.
    fn secp256k1_signature_for_test(
        secret_key: &k256::Scalar,
        predecessor: &AccountId,
        path: &str,
        payload: &Payload,
    ) -> dtos::K256Signature {
        let derivation_path = derive_tweak(predecessor, path);
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let derived_secret_key = derive_secret_key(&secret_key_ec, &derivation_path);
        let signing_key = SigningKey::from_bytes(&derived_secret_key.to_bytes()).unwrap();
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(payload.as_ecdsa().unwrap())
            .unwrap();
        dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id)
    }

    fn test_signature_common(success: bool, legacy_v1_api: bool, protocol: dtos::Protocol) {
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(protocol, dtos::DomainPurpose::Sign, &mut OsRng);
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let mut payload_hash = [0u8; 32];
        OsRng.fill_bytes(&mut payload_hash);
        let payload = Payload::from_legacy_ecdsa(payload_hash);
        let key_path = "m/44'\''/60'\''/0'\''/0/0".to_string();

        let request: dtos::SignRequestArgs = if legacy_v1_api {
            serde_json::from_value(serde_json::json!({
                "payload": payload_hash,
                "key_version": 0,
                "path": key_path,
            }))
            .unwrap()
        } else {
            dtos::SignRequestArgs {
                payload: payload.clone(),
                path: key_path.clone(),
                domain_id: DomainId::legacy_ecdsa_id(),
            }
        };
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            payload.clone(),
            &context.predecessor_account_id,
            &request.path,
        );
        contract.sign(request);
        contract.get_pending_request(&signature_request).unwrap();

        let valid_signature = secp256k1_signature_for_test(
            &secret_key,
            &context.predecessor_account_id,
            &key_path,
            &payload,
        );
        let signature_response = if success {
            dtos::SignatureResponse::Secp256k1(valid_signature)
        } else {
            // submit an incorrect signature to make the respond call fail
            let mut bad_sig = valid_signature;
            bad_sig.s = dtos::K256Scalar::from([2; 32]);
            dtos::SignatureResponse::Secp256k1(bad_sig)
        };

        with_active_participant_and_attested_context(&contract);

        match contract.respond(signature_request.clone(), signature_response.clone()) {
            Ok(_) => {
                assert!(success);
                contract
                    .return_signature_and_clean_state_on_success(
                        signature_request.clone(),
                        Ok(signature_response),
                    )
                    .detach();

                assert!(contract.get_pending_request(&signature_request).is_none(),);
            }
            Err(_) => assert!(!success),
        }
    }

    #[test]
    fn respond__should_succeed_when_response_is_valid_and_request_exists() {
        for protocol in [dtos::Protocol::CaitSith, dtos::Protocol::DamgardEtAl] {
            test_signature_common(true, false, protocol);
            test_signature_common(false, false, protocol);
        }
    }

    #[test]
    fn respond__should_succeed_when_response_is_valid_and_request_exists_legacy() {
        for protocol in [dtos::Protocol::CaitSith, dtos::Protocol::DamgardEtAl] {
            test_signature_common(true, true, protocol);
            test_signature_common(false, true, protocol);
        }
    }

    #[test]
    fn test_signature_timeout() {
        let (context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let payload = Payload::from_legacy_ecdsa([0u8; 32]);
        let key_path = "m/44'\''/60'\''/0'\''/0/0".to_string();

        let request = dtos::SignRequestArgs {
            payload: payload.clone(),
            path: key_path.clone(),
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            payload,
            &context.predecessor_account_id,
            &request.path,
        );
        contract.sign(request);
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(
            contract.return_signature_and_clean_state_on_success(
                signature_request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(contract.get_pending_request(&signature_request).is_none());
    }

    #[test]
    fn test_signature_timeout__request_in_neither_map_still_schedules_fail() {
        // given
        let (context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            Payload::from_legacy_ecdsa([0u8; 32]),
            &context.predecessor_account_id,
            "m/44'\''/60'\''/0'\''/0/0",
        );
        assert_matches!(contract.get_pending_request(&signature_request), None);

        // when
        let result = contract.return_signature_and_clean_state_on_success(
            signature_request,
            Err(PromiseError::Failed),
        );

        // then
        // We can't assert_matches! on [near_sdk::PromiseOrValue] it is not Debug
        match result {
            PromiseOrValue::Promise(_promise) => {}
            PromiseOrValue::Value(_) => panic!("result should be a promise"),
        }
    }

    #[test]
    fn test_signature_success__returns_value_directly() {
        // given
        let (context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            Payload::from_legacy_ecdsa([0u8; 32]),
            &context.predecessor_account_id,
            "m/44'\''/60'\''/0'\''/0/0",
        );
        let signature_response = dtos::SignatureResponse::Secp256k1(dtos::K256Signature {
            big_r: dtos::K256AffinePoint::from(k256::AffinePoint::GENERATOR),
            s: dtos::K256Scalar::from(k256::Scalar::ONE),
            recovery_id: 0,
        });

        // when
        let result = contract.return_signature_and_clean_state_on_success(
            signature_request,
            Ok(signature_response.clone()),
        );

        // then
        match result {
            PromiseOrValue::Value(resp) => assert_eq!(resp, signature_response),
            PromiseOrValue::Promise(_) => panic!("Expected Value, got Promise"),
        }
    }

    #[test]
    fn sign__should_queue_duplicate_requests_and_drain_all_on_respond() {
        // Given
        let (context, mut contract, secret_key) = basic_setup_with_protocol(
            dtos::Protocol::CaitSith,
            dtos::DomainPurpose::Sign,
            &mut OsRng,
        );
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let payload = Payload::from_legacy_ecdsa([7u8; 32]);
        let path = "duplicate_requests_test".to_string();
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            payload.clone(),
            &context.predecessor_account_id,
            &path,
        );
        let request_args = dtos::SignRequestArgs {
            payload: payload.clone(),
            path: path.clone(),
            domain_id: DomainId::legacy_ecdsa_id(),
        };

        // When: same caller submits the same request twice in close succession.
        contract.sign(request_args.clone());
        contract.sign(request_args);

        // Then: both yields are queued under one map entry.
        assert_eq!(
            contract
                .pending_signature_requests
                .get(&signature_request)
                .map(|q| q.len()),
            Some(2),
            "duplicate sign requests should fan out into a queue of two",
        );

        // When: a single valid response is delivered.
        let signature_response = dtos::SignatureResponse::Secp256k1(secp256k1_signature_for_test(
            &secret_key,
            &context.predecessor_account_id,
            &path,
            &payload,
        ));

        with_active_participant_and_attested_context(&contract);
        contract
            .respond(signature_request.clone(), signature_response)
            .expect("respond should succeed");

        // Then: the entire queue is drained — both queued yields received the response.
        assert!(
            contract
                .pending_signature_requests
                .get(&signature_request)
                .is_none()
        );
    }

    #[test]
    fn add_signature_request__should_panic_when_pending_queue_is_full() {
        // Given: a contract with a queue already at the fan-out cap for some request key.
        let (context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            Payload::from_legacy_ecdsa([3u8; 32]),
            &context.predecessor_account_id,
            "m/44'\''/60'\''/0'\''/0/0",
        );
        for i in 0..MAX_PENDING_REQUEST_FAN_OUT {
            contract.add_signature_request(signature_request.clone(), [i; 32]);
        }
        assert_eq!(
            contract
                .pending_signature_requests
                .get(&signature_request)
                .map(|q| q.len()),
            Some(usize::from(MAX_PENDING_REQUEST_FAN_OUT)),
        );

        // When: one more append is attempted.
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            contract.add_signature_request(signature_request.clone(), [0xff; 32]);
        }));

        // Then: it panics with the typed cap-exceeded error and leaves the queue untouched.
        let err = result.expect_err("appending past the cap should panic");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            msg.contains("Pending-request queue is full"),
            "unexpected panic message: {msg}",
        );
        assert_eq!(
            contract
                .pending_signature_requests
                .get(&signature_request)
                .map(|q| q.len()),
            Some(usize::from(MAX_PENDING_REQUEST_FAN_OUT)),
            "queue should not have grown past the cap",
        );
    }

    #[test]
    fn return_signature_and_clean_state_on_success__should_pop_only_oldest_yield_on_timeout() {
        // Given: three duplicate sign requests queued for the same key.
        let (context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let signature_request = dtos::SignatureRequest::new(
            DomainId::default(),
            Payload::from_legacy_ecdsa([0u8; 32]),
            &context.predecessor_account_id,
            "m/44'\''/60'\''/0'\''/0/0",
        );
        for i in 0..3u8 {
            contract.add_signature_request(signature_request.clone(), [i; 32]);
        }
        assert_eq!(
            contract
                .pending_signature_requests
                .get(&signature_request)
                .map(|q| q.len()),
            Some(3),
        );

        // When: the oldest yield times out.
        let _ = contract.return_signature_and_clean_state_on_success(
            signature_request.clone(),
            Err(PromiseError::Failed),
        );

        // Then: the queue still contains the two remaining yields, oldest-first.
        let remaining = contract
            .pending_signature_requests
            .get(&signature_request)
            .cloned()
            .expect("entry must remain while sibling yields are still pending");
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].data_id, [1u8; 32]);
        assert_eq!(remaining[1].data_id, [2u8; 32]);

        // When: the last two yields time out, the map entry is fully cleaned up.
        let _ = contract.return_signature_and_clean_state_on_success(
            signature_request.clone(),
            Err(PromiseError::Failed),
        );
        let _ = contract.return_signature_and_clean_state_on_success(
            signature_request.clone(),
            Err(PromiseError::Failed),
        );

        // Then: the entry is gone.
        assert!(
            contract
                .pending_signature_requests
                .get(&signature_request)
                .is_none()
        );
    }

    #[rstest]
    #[case(dtos::Protocol::CaitSith, dtos::DomainPurpose::ForeignTx)]
    #[case(dtos::Protocol::ConfidentialKeyDerivation, dtos::DomainPurpose::CKD)]
    #[should_panic(expected = "this method requires Sign")]
    fn sign__should_reject_non_sign_domain(
        #[case] protocol: dtos::Protocol,
        #[case] purpose: dtos::DomainPurpose,
    ) {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _sk) = basic_setup_with_protocol(protocol, purpose, &mut rng);

        // When
        contract.sign(dtos::SignRequestArgs {
            payload: Payload::from_legacy_ecdsa([7u8; 32]),
            path: "test".to_string(),
            domain_id: DomainId::default(),
        });
    }
}
