//! The respond method of V2 foreign transaction requests: a signed outcome
//! answers the one request stored under its yield id.

use crate::errors::{Error, InvalidParameters, InvalidState, TeeError};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{env, log, near};

#[near]
impl MpcContract {
    /// Answers the V2 request stored under `yield_id` with `outcome`. Only
    /// attested participants may call it.
    ///
    /// `signature` must sign the [`dtos::ForeignTxSignPayload::V2`] built from
    /// the stored request, `yield_id` and `outcome`, under the root key of the
    /// request's domain. The method then resumes the yield with a
    /// [`dtos::VerifyForeignTransactionResponseV2`] and removes the request, so
    /// a signature answers one request once.
    #[handle_result]
    pub fn respond_verify_foreign_tx_v2(
        &mut self,
        yield_id: dtos::YieldId,
        outcome: dtos::ForeignTxVerificationOutcome,
        signature: dtos::SignatureResponse,
    ) -> Result<(), Error> {
        let signer = Self::assert_caller_is_signer();
        log!(
            "respond_verify_foreign_tx_v2: signer={}, yield_id={:?}",
            &signer,
            &yield_id
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        let Some(pending) = self.pending_verify_foreign_tx_v2_requests.get(&yield_id) else {
            return Err(InvalidParameters::RequestNotFound.into());
        };
        let payload_hash = pending
            .sign_payload(yield_id, outcome.clone())
            .compute_msg_hash()
            .unwrap_or_else(|err| env::panic_str(&format!("hashing the sign payload: {err}")));
        self.verify_foreign_tx_signature(pending.domain_id, &payload_hash, &signature)?;

        let response = dtos::VerifyForeignTransactionResponseV2 {
            payload_hash,
            signature,
            request_block_height: pending.request_block_height,
            yield_id,
            outcome,
        };
        let response_bytes = serde_json::to_vec(&response)
            .unwrap_or_else(|err| env::panic_str(&format!("encoding the response: {err}")));
        // The runtime refuses the resume once the yield timed out. The timeout
        // callback then removes the request.
        if !env::promise_yield_resume_with_yield_id(&yield_id.0, response_bytes) {
            return Err(InvalidParameters::RequestNotFound.into());
        }
        self.pending_verify_foreign_tx_v2_requests.remove(&yield_id);
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::foreign_chain::test_utils::{
        announced_yield_ids, bitcoin_request_v2, make_chains_available, sign_payload_hash,
    };
    use crate::api::test_utils::{
        SharedSecretKey, basic_setup_with_protocol, make_public_key_for_curve,
        participant_account_ids, prepay_and_attest_all_participants,
        with_active_participant_and_attested_context,
    };
    use crate::dto_mapping::IntoInterfaceType;
    use crate::errors::RespondError;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
    use crate::primitives::test_utils::{bogus_tee_verifier_account_id, gen_participants};
    use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
    use crate::state::ProtocolContractState;
    use dtos::{
        BlockHeight, Curve, DomainConfig, DomainId, DomainPurpose, ForeignTxSignPayloadV2,
        ForeignTxVerificationNegativeVerdict, ForeignTxVerificationOutcome, Protocol,
        ReconstructionThreshold, YieldId,
    };
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, NearToken, PromiseError, PromiseOrValue, testing_env};
    use rand::SeedableRng;
    use rstest::rstest;
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    const VERIFIED: ForeignTxVerificationOutcome = ForeignTxVerificationOutcome::Verified {};

    struct RespondSetup {
        contract: MpcContract,
        secret_key: k256::Scalar,
    }

    /// Calls come from an attested participant. The mocked blockchain keeps
    /// the yields that [`MpcContract::read_rpc`] creates until the next
    /// `testing_env!`.
    fn setup_with_an_attested_participant_calling() -> RespondSetup {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, dtos::DomainPurpose::ForeignTx, &mut rng);
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        with_active_participant_and_attested_context(&contract);
        RespondSetup {
            contract,
            secret_key,
        }
    }

    struct TwoDomainSetup {
        contract: MpcContract,
        secret_keys: BTreeMap<DomainId, k256::Scalar>,
    }

    /// Like [`setup_with_an_attested_participant_calling`], with two ForeignTx
    /// domains, each under its own key.
    fn setup_with_two_foreign_tx_domains() -> TwoDomainSetup {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let domains = [DomainId(0), DomainId(1)].map(|id| DomainConfig {
            id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(3),
            purpose: DomainPurpose::ForeignTx,
        });
        let mut secret_keys = BTreeMap::new();
        let mut keys = vec![];
        for domain in &domains {
            let (public_key, secret_key) = make_public_key_for_curve(Curve::Secp256k1, &mut rng);
            let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
                unreachable!();
            };
            secret_keys.insert(domain.id, secret_key);
            keys.push(KeyForDomain {
                domain_id: domain.id,
                key: public_key.try_into().unwrap(),
                attempt: AttemptId::new(),
            });
        }
        let parameters =
            GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
                .unwrap();
        let mut contract = MpcContract::init_running(
            domains.to_vec(),
            DomainId(2),
            (&Keyset::new(EpochId::new(0), keys)).into_dto_type(),
            (&parameters).into_dto_type(),
            bogus_tee_verifier_account_id(),
            None,
        )
        .unwrap();
        prepay_and_attest_all_participants(&mut contract);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        with_active_participant_and_attested_context(&contract);
        TwoDomainSetup {
            contract,
            secret_keys,
        }
    }

    fn submit_request_to(contract: &mut MpcContract, domain_id: DomainId) -> YieldId {
        contract.read_rpc(dtos::VerifyForeignTransactionRequestV2 {
            domain_id,
            ..bitcoin_request_v2()
        });
        let [yield_id] = announced_yield_ids()[..] else {
            panic!("expected exactly one yield created event");
        };
        yield_id
    }

    /// Moves the contract from Running to Initializing with every
    /// participant's vote for a new domain.
    fn start_adding_a_domain(contract: &mut MpcContract) {
        let new_domain = DomainConfig {
            id: DomainId(1),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(3),
            purpose: DomainPurpose::Sign,
        };
        for account_id in participant_account_ids(contract) {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id)
                    .build()
            );
            contract.vote_add_domains(vec![new_domain.clone()]).unwrap();
        }
        assert_matches!(
            contract.protocol_state,
            ProtocolContractState::Initializing(_)
        );
    }

    fn submit_requests<const N: usize>(contract: &mut MpcContract) -> [YieldId; N] {
        for _ in 0..N {
            contract.read_rpc(bitcoin_request_v2());
        }
        announced_yield_ids().try_into().unwrap()
    }

    fn payload_for(
        yield_id: YieldId,
        outcome: ForeignTxVerificationOutcome,
    ) -> ForeignTxSignPayloadV2 {
        let request = bitcoin_request_v2();
        ForeignTxSignPayloadV2 {
            request: request.request.clone(),
            expected_values_hash: request.expected_values_hash().unwrap(),
            request_block_height: BlockHeight::new(env::block_height()),
            yield_id,
            outcome,
        }
    }

    fn sign(secret_key: &k256::Scalar, payload: ForeignTxSignPayloadV2) -> dtos::SignatureResponse {
        let payload_hash = dtos::ForeignTxSignPayload::V2(payload)
            .compute_msg_hash()
            .unwrap();
        sign_payload_hash(secret_key, &payload_hash)
    }

    fn is_open(contract: &MpcContract, yield_id: &YieldId) -> bool {
        contract
            .pending_verify_foreign_tx_v2_requests
            .get(yield_id)
            .is_some()
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_answer_only_the_request_with_that_yield_id() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [answered, other] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(answered, VERIFIED));

        // When
        let result = contract.respond_verify_foreign_tx_v2(answered, VERIFIED, signature);

        // Then
        assert_matches!(result, Ok(()));
        assert!(!is_open(&contract, &answered));
        assert!(is_open(&contract, &other));
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_a_signature_for_another_request() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [signed_for, other] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(signed_for, VERIFIED));

        // When
        let result = contract.respond_verify_foreign_tx_v2(other, VERIFIED, signature);

        // Then
        assert_matches!(result, Err(Error::Respond(RespondError::InvalidSignature)));
        assert!(is_open(&contract, &signed_for));
        assert!(is_open(&contract, &other));
    }

    #[rstest]
    #[case::outcome(|payload| ForeignTxSignPayloadV2 {
        outcome: ForeignTxVerificationOutcome::Negative {
            verdict: ForeignTxVerificationNegativeVerdict::TransactionNotFound,
        },
        ..payload
    })]
    #[case::yield_id(|payload| ForeignTxSignPayloadV2 { yield_id: YieldId([9u8; 32]), ..payload })]
    #[case::request_block_height(|payload| ForeignTxSignPayloadV2 {
        request_block_height: BlockHeight::new(env::block_height() + 1),
        ..payload
    })]
    #[case::expected_values_hash(|payload| ForeignTxSignPayloadV2 {
        expected_values_hash: dtos::Hash256([9u8; 32]),
        ..payload
    })]
    #[case::request(|payload| ForeignTxSignPayloadV2 {
        request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: [8u8; 32].into(),
            confirmations: 2.into(),
            extractors: [dtos::BitcoinExtractor::BlockHash].into(),
        }),
        ..payload
    })]
    fn respond_verify_foreign_tx_v2__should_reject_a_signature_over_another_payload(
        #[case] change_signed_payload: fn(ForeignTxSignPayloadV2) -> ForeignTxSignPayloadV2,
    ) {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(
            &secret_key,
            change_signed_payload(payload_for(yield_id, VERIFIED)),
        );

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(result, Err(Error::Respond(RespondError::InvalidSignature)));
        assert!(is_open(&contract, &yield_id));
    }

    #[rstest]
    #[case::first_domain(DomainId(0))]
    #[case::second_domain(DomainId(1))]
    fn respond_verify_foreign_tx_v2__should_accept_a_signature_under_the_key_of_the_request_domain(
        #[case] request_domain: DomainId,
    ) {
        // Given
        let TwoDomainSetup {
            mut contract,
            secret_keys,
        } = setup_with_two_foreign_tx_domains();
        let yield_id = submit_request_to(&mut contract, request_domain);
        let signature = sign(
            &secret_keys[&request_domain],
            payload_for(yield_id, VERIFIED),
        );

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(result, Ok(()));
        assert!(!is_open(&contract, &yield_id));
    }

    #[rstest]
    #[case::first_domain_signed_by_the_second(DomainId(0), DomainId(1))]
    #[case::second_domain_signed_by_the_first(DomainId(1), DomainId(0))]
    fn respond_verify_foreign_tx_v2__should_reject_a_signature_under_the_key_of_another_domain(
        #[case] request_domain: DomainId,
        #[case] signing_domain: DomainId,
    ) {
        // Given
        let TwoDomainSetup {
            mut contract,
            secret_keys,
        } = setup_with_two_foreign_tx_domains();
        let yield_id = submit_request_to(&mut contract, request_domain);
        let signature = sign(
            &secret_keys[&signing_domain],
            payload_for(yield_id, VERIFIED),
        );

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(result, Err(Error::Respond(RespondError::InvalidSignature)));
        assert!(is_open(&contract, &yield_id));
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_a_signature_of_another_scheme() {
        // Given
        let RespondSetup { mut contract, .. } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = dtos::SignatureResponse::Ed25519 {
            signature: dtos::Ed25519Signature::from([7u8; 64]),
        };

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(
            result,
            Err(Error::Respond(RespondError::SignatureSchemeMismatch { .. }))
        );
        assert!(is_open(&contract, &yield_id));
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_a_response_while_the_protocol_is_not_running() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(yield_id, VERIFIED));
        start_adding_a_domain(&mut contract);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidState(InvalidState::ProtocolStateNotRunning))
        );
        assert!(is_open(&contract, &yield_id));
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_a_response_while_the_contract_does_not_accept_requests()
     {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(yield_id, VERIFIED));
        contract.accept_requests = false;

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(result, Err(Error::TeeError(TeeError::TeeValidationFailed)));
        assert!(is_open(&contract, &yield_id));
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_a_second_response_to_the_same_request() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(yield_id, VERIFIED));
        contract
            .respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature.clone())
            .unwrap();

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(InvalidParameters::RequestNotFound))
        );
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_an_unknown_yield_id_and_keep_the_request_open() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let unknown = YieldId([9u8; 32]);
        let signature = sign(&secret_key, payload_for(unknown, VERIFIED));

        // When
        let result = contract.respond_verify_foreign_tx_v2(unknown, VERIFIED, signature);

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(InvalidParameters::RequestNotFound))
        );
        assert!(is_open(&contract, &yield_id));
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_reject_a_response_after_the_timeout_callback() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(yield_id, VERIFIED));
        contract
            .return_verify_foreign_tx_v2_and_clean_state_on_timeout(
                yield_id,
                Err(PromiseError::Failed),
            )
            .detach();

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(InvalidParameters::RequestNotFound))
        );
    }

    #[test]
    fn respond_verify_foreign_tx_v2__should_leave_the_request_to_the_timeout_callback_when_the_yield_timed_out()
     {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(yield_id, VERIFIED));
        // A new mocked blockchain has no pending yields, so it refuses the resume
        // as the runtime does after a timeout.
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(InvalidParameters::RequestNotFound))
        );
        assert!(is_open(&contract, &yield_id));
    }

    #[test]
    fn return_verify_foreign_tx_v2_and_clean_state_on_timeout__should_return_the_response_of_respond_verify_foreign_tx_v2()
     {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let payload = payload_for(yield_id, VERIFIED);
        let signature = sign(&secret_key, payload.clone());
        contract
            .respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature.clone())
            .unwrap();
        let response = dtos::VerifyForeignTransactionResponseV2 {
            payload_hash: dtos::ForeignTxSignPayload::V2(payload.clone())
                .compute_msg_hash()
                .unwrap(),
            signature,
            request_block_height: payload.request_block_height,
            yield_id,
            outcome: VERIFIED,
        };

        // When
        let result = contract
            .return_verify_foreign_tx_v2_and_clean_state_on_timeout(yield_id, Ok(response.clone()));

        // Then
        // assert_matches! requires Debug, and PromiseOrValue does not implement it
        let PromiseOrValue::Value(returned) = result else {
            panic!("expected the response, not a promise");
        };
        assert_eq!(returned, response);
        assert!(!is_open(&contract, &yield_id));
    }

    #[test]
    #[should_panic(expected = "Caller must be an attested participant")]
    fn respond_verify_foreign_tx_v2__should_reject_a_caller_that_is_not_an_attested_participant() {
        // Given
        let RespondSetup {
            mut contract,
            secret_key,
        } = setup_with_an_attested_participant_calling();
        let [yield_id] = submit_requests(&mut contract);
        let signature = sign(&secret_key, payload_for(yield_id, VERIFIED));
        let outsider = AccountId::from_str("outsider.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(outsider.clone())
                .predecessor_account_id(outsider)
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );

        // When
        let _ = contract.respond_verify_foreign_tx_v2(yield_id, VERIFIED, signature);
    }
}
