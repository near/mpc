//! Foreign-chain transaction verification: the verify request path, its response
//! callback and the pending-request view.

use crate::crypto_shared::types::PublicKeyExtended;
use crate::dto_mapping::args_into_verify_foreign_tx_request;
use crate::errors::{Error, InvalidParameters, InvalidState, RespondError, TeeError};
use crate::primitives::signature::YieldIndex;
use crate::{MpcContract, MpcContractExt, pending_requests};
use dtos::DomainPurpose;
use near_mpc_contract_interface::deposits::SIGN_DEPOSIT_YOCTONEAR;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    self as dtos, VerifyForeignTransactionRequest, VerifyForeignTransactionRequestArgs,
    VerifyForeignTransactionResponse,
};
use near_sdk::{CryptoHash, Gas, NearToken, Promise, PromiseError, PromiseOrValue, env, log, near};

#[near]
impl MpcContract {
    fn add_verify_foreign_tx_request(
        &mut self,
        request: VerifyForeignTransactionRequest,
        data_id: CryptoHash,
    ) {
        pending_requests::push_pending_yield(
            &mut self.pending_verify_foreign_tx_requests,
            request,
            data_id,
        );
    }

    /// Submit a verification + signing request for a foreign chain transaction.
    /// MPC nodes will verify the transaction on the foreign chain before signing.
    /// The signed payload is derived from the transaction ID (hash of tx_id).
    #[handle_result]
    #[payable]
    pub fn verify_foreign_transaction(&mut self, request: VerifyForeignTransactionRequestArgs) {
        log!(
            "verify_foreign_transaction: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );

        self.check_request_preconditions(
            request.domain_id,
            DomainPurpose::ForeignTx,
            Gas::from_tgas(self.config.sign_call_gas_attachment_requirement_tera_gas),
            NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
        );

        let requested_chain = request.request.chain();
        let available_chains = self.get_available_foreign_chains();
        if !available_chains.contains(&requested_chain) {
            env::panic_str(
                &InvalidParameters::ForeignChainNotAvailable {
                    requested: requested_chain,
                }
                .to_string(),
            );
        }

        let callback_gas = Gas::from_tgas(
            self.config
                .return_signature_and_clean_state_on_success_call_tera_gas,
        );

        let request = args_into_verify_foreign_tx_request(request);
        let callback_args = serde_json::to_vec(&(&request,)).unwrap();
        self.enqueue_yield_request(
            method_names::RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS,
            callback_args,
            callback_gas,
            move |this, id| this.add_verify_foreign_tx_request(request, id),
        );
    }

    #[handle_result]
    pub fn respond_verify_foreign_tx(
        &mut self,
        request: VerifyForeignTransactionRequest,
        response: VerifyForeignTransactionResponse,
    ) -> Result<(), Error> {
        let signer = Self::assert_caller_is_signer();

        log!(
            "respond_verify_foreign_tx: signer={}, request={:?}",
            &signer,
            &request
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        if let Some(expected_payload_hash) = &request.expected_payload_hash
            && &response.payload_hash != expected_payload_hash
        {
            return Err(RespondError::UnexpectedPayloadHash.into());
        }

        let domain = request.domain_id;
        let public_key = self.public_key_extended(domain.0.into())?;

        let signature_is_valid = match (&response.signature, public_key) {
            (
                dtos::SignatureResponse::Secp256k1(signature_response),
                PublicKeyExtended::Secp256k1 { near_public_key },
            ) => {
                let secp_pk = dtos::Secp256k1PublicKey::try_from(&near_public_key)
                    .expect("Secp256k1 variant always has a secp256k1 key");

                let payload_hash: [u8; 32] = response.payload_hash.0;

                // Check the signature is correct against the root public key
                near_mpc_signature_verifier::verify_ecdsa_signature(
                    signature_response,
                    &payload_hash,
                    &secp_pk,
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
            &mut self.pending_verify_foreign_tx_requests,
            &request,
            serde_json::to_vec(&response).unwrap(),
        )
    }

    /// Presence check for a pending foreign-tx verification request, exposed as a
    /// view call.
    ///
    /// See [`Self::get_pending_request`] for the contract: the returned [`YieldIndex`]
    /// is an arbitrary representative of a fan-out queue, not "the" yield. Only the
    /// `Some`/`None` distinction is meaningful.
    pub fn get_pending_verify_foreign_tx_request(
        &self,
        request: &VerifyForeignTransactionRequest,
    ) -> Option<YieldIndex> {
        self.pending_verify_foreign_tx_requests
            .get(request)
            .and_then(|q| q.first().cloned())
    }

    /// Yield-resume callback for a single queued foreign-tx verification request.
    ///
    /// On success, returns the verification response to the original caller. On
    /// timeout, pops this yield's slot (the head of the FIFO fan-out queue) from the
    /// pending-request map and fires `fail_on_timeout` to fail the original
    /// transaction. Sibling yields queued under the same request key remain pending
    /// and are cleaned up by their own timeouts (or drained together by a subsequent
    /// `respond_verify_foreign_tx`).
    #[private]
    pub fn return_verify_foreign_tx_and_clean_state_on_success(
        &mut self,
        request: VerifyForeignTransactionRequest,
        #[callback_result] response: Result<VerifyForeignTransactionResponse, PromiseError>,
    ) -> PromiseOrValue<VerifyForeignTransactionResponse> {
        match response {
            Ok(response) => PromiseOrValue::Value(response),
            Err(_) => {
                pending_requests::pop_oldest_pending_yield(
                    &mut self.pending_verify_foreign_tx_requests,
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
        SharedSecretKey, basic_setup_with_protocol, participant_account_ids,
        register_foreign_chains_config_for, whitelist_chain,
        with_active_participant_and_attested_context,
    };

    use assert_matches::assert_matches;
    use dtos::{DomainId, ForeignTxSignPayload, Protocol};
    use k256::ecdsa::SigningKey;
    use k256::{self, Secp256k1, elliptic_curve};

    use near_mpc_contract_interface::types::{
        BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, ExtractedValue,
        ForeignTxPayloadVersion, ForeignTxSignPayloadV1,
    };
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, testing_env};
    use rand::SeedableRng;

    use rstest::rstest;
    use std::panic;
    use std::str::FromStr;

    /// Whitelists the chains and registers them for all participants, making them available.
    fn make_chains_available(
        contract: &mut MpcContract,
        chains: impl IntoIterator<Item = dtos::ForeignChain>,
    ) {
        let chains: Vec<_> = chains.into_iter().collect();
        for chain in &chains {
            whitelist_chain(contract, *chain);
        }
        for account_id in participant_account_ids(contract) {
            register_foreign_chains_config_for(contract, &account_id, chains.iter().copied());
        }
    }

    #[test]
    fn verify_foreign_transaction__should_queue_duplicates_from_different_callers() {
        // Given: two different callers will submit the same foreign-tx verification request.
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };

        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When: caller alice submits the request.
        let alice = AccountId::from_str("alice.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(alice.clone())
                .predecessor_account_id(alice)
                .current_account_id(context.current_account_id.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        contract.verify_foreign_transaction(request_args.clone());

        // And: caller bob submits the identical request — a different account would today
        // be blocked from receiving a response by alice's submission.
        let bob = AccountId::from_str("bob.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(bob.clone())
                .predecessor_account_id(bob)
                .current_account_id(context.current_account_id.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        contract.verify_foreign_transaction(request_args);

        // Then: both yields are queued under the single (caller-agnostic) request key.
        assert_eq!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .map(|q| q.len()),
            Some(2),
            "duplicate foreign-tx requests from different callers should fan out",
        );

        // When: a single valid response is delivered.
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let payload_hash_arr = payload.compute_msg_hash().unwrap().0;
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let signing_key = SigningKey::from_bytes(&secret_key_ec.to_bytes()).unwrap();
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&payload_hash_arr)
            .unwrap();
        let response = VerifyForeignTransactionResponse {
            payload_hash: payload.compute_msg_hash().unwrap(),
            signature: dtos::SignatureResponse::Secp256k1(
                dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id),
            ),
        };

        with_active_participant_and_attested_context(&contract);
        contract
            .respond_verify_foreign_tx(request.clone(), response)
            .expect("respond_verify_foreign_tx should succeed");

        // Then: both queued yields are drained from the single map entry.
        assert!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .is_none()
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_succeed_when_response_is_valid_and_request_exists() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };

        // When
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        contract
            .get_pending_verify_foreign_tx_request(&request)
            .unwrap();
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);

        with_active_participant_and_attested_context(&contract);

        // Then
        match contract.respond_verify_foreign_tx(request.clone(), response.clone()) {
            Ok(_) => {
                contract
                    .return_verify_foreign_tx_and_clean_state_on_success(
                        request.clone(),
                        Ok(response),
                    )
                    .detach();

                assert!(
                    contract
                        .get_pending_verify_foreign_tx_request(&request)
                        .is_none(),
                );
            }
            Err(_) => panic!("respond_verify_foreign_tx should not fail"),
        }
    }

    #[test]
    fn respond_verify_foreign_tx__should_reject_response_with_unexpected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx(request.clone(), response);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::Respond(RespondError::UnexpectedPayloadHash)
        );
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_some(),
            "the pending request must remain unresolved",
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_succeed_when_response_matches_expected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let rpc_request = dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: [7u8; 32].into(),
            confirmations: 2.into(),
            extractors: vec![BitcoinExtractor::BlockHash],
        });
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: rpc_request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(payload.compute_msg_hash().unwrap()),
            request: rpc_request,
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx(request.clone(), response);

        // Then
        assert!(
            result.is_ok(),
            "response matching the expected payload hash must be accepted: {result:?}",
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_reject_request_with_erased_expected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let tampered_request = VerifyForeignTransactionRequest {
            expected_payload_hash: None,
            ..request.clone()
        };
        let result = contract.respond_verify_foreign_tx(tampered_request, response);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidParameters(InvalidParameters::RequestNotFound)
        );
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_some(),
            "the pending request must remain unresolved",
        );
    }

    fn sign_foreign_tx_payload(
        secret_key: &k256::Scalar,
        payload: &ForeignTxSignPayload,
    ) -> VerifyForeignTransactionResponse {
        let payload_hash = payload.compute_msg_hash().unwrap();
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let secret_key = SigningKey::from_bytes(&secret_key_ec.to_bytes()).unwrap();
        let (signature, recovery_id) = secret_key
            .sign_prehash_recoverable(&payload_hash.0)
            .unwrap();
        let signature = dtos::SignatureResponse::Secp256k1(
            dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id),
        );
        VerifyForeignTransactionResponse {
            payload_hash,
            signature,
        }
    }

    #[test]
    fn test_verify_foreign_tx_timeout() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When
        contract.verify_foreign_transaction(request_args);

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(
            contract.return_verify_foreign_tx_and_clean_state_on_success(
                request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_none()
        );
    }

    #[rstest]
    #[case(Protocol::CaitSith, DomainPurpose::Sign)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::CKD)]
    #[should_panic(expected = "this method requires ForeignTx")]
    fn verify_foreign_tx__should_reject_non_foreign_tx_domain(
        #[case] protocol: Protocol,
        #[case] purpose: DomainPurpose,
    ) {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _sk) = basic_setup_with_protocol(protocol, purpose, &mut rng);

        // When
        contract.verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        });
    }

    #[test]
    #[should_panic(expected = "Requested foreign chain, Bitcoin, is not available.")]
    fn verify_foreign_tx__should_reject_chain_not_in_policy() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Solana]);
        testing_env!(context.clone());

        // When - requesting Bitcoin which is not in the policy
        contract.verify_foreign_transaction(bitcoin_request_args());
    }

    #[test]
    #[should_panic(expected = "Requested foreign chain, Bitcoin, is not available.")]
    fn verify_foreign_tx__should_reject_chain_covered_by_all_participants_but_not_whitelisted() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        for account_id in participant_account_ids(&contract) {
            register_foreign_chains_config_for(
                &mut contract,
                &account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }
        testing_env!(context.clone());

        // When
        contract.verify_foreign_transaction(bitcoin_request_args());
    }

    #[test]
    #[should_panic(expected = "Requested foreign chain, Bitcoin, is not available.")]
    fn verify_foreign_tx__should_reject_whitelisted_chain_covered_by_fewer_than_threshold() {
        // Given: 4 participants, ForeignTx reconstruction threshold 3; only 2 cover Bitcoin.
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participant_account_ids(&contract).iter().take(2) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }
        testing_env!(context.clone());

        // When
        contract.verify_foreign_transaction(bitcoin_request_args());
    }

    #[test]
    fn verify_foreign_tx__should_accept_chain_covered_by_threshold_of_participants() {
        // Given: 4 participants, ForeignTx reconstruction threshold 3; only 3 cover Bitcoin.
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participant_account_ids(&contract).iter().take(3) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }
        testing_env!(context.clone());
        let request_args = bitcoin_request_args();
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When
        contract.verify_foreign_transaction(request_args);

        // Then
        assert!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .is_some()
        );
    }

    fn bitcoin_request_args() -> VerifyForeignTransactionRequestArgs {
        VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        }
    }
}
