use near_mpc_contract_interface::types::{
    BlockHeight, ForeignTxSignPayload, ForeignTxSignPayloadV2, ForeignTxVerificationOutcome,
    PublicKey, VerifyForeignTransactionRequestV2, VerifyForeignTransactionResponseV2, YieldId,
};

use super::{VerifyForeignChainError, verify_signed_payload_hash};

/// Checks the signature on a [`VerifyForeignTransactionResponseV2`] against the
/// [`VerifyForeignTransactionRequestV2`] it answers.
///
/// The verifier rebuilds the signed [`ForeignTxSignPayload::V2`] from the request and from the
/// response fields. It takes the yield id and the request block height from the response, so a
/// response to an earlier identical request also passes. A caller must:
///
/// - pass the root public key of the request's [`VerifyForeignTransactionRequestV2::domain_id`],
/// - accept each [`VerifiedForeignTxResponseV2::yield_id`] only once, and store the ids it
///   consumed,
/// - accept a negative outcome only when [`VerifiedForeignTxResponseV2::request_block_height`] is
///   at or above a NEAR block height the caller obtained independently of the response.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForeignChainSignatureVerifierV2 {
    request: VerifyForeignTransactionRequestV2,
}

/// A [`VerifyForeignTransactionResponseV2`] whose signature
/// [`ForeignChainSignatureVerifierV2`] accepted.
#[must_use = "a verified response can still answer an earlier request: check its yield id"]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedForeignTxResponseV2 {
    request_block_height: BlockHeight,
    yield_id: YieldId,
    outcome: ForeignTxVerificationOutcome,
}

impl ForeignChainSignatureVerifierV2 {
    pub fn new(request: VerifyForeignTransactionRequestV2) -> Self {
        Self { request }
    }

    /// Succeeds only if the network signed a [`ForeignTxVerificationOutcome::Verified`] answer to
    /// the request under `public_key`. A signed negative or inconclusive outcome is an error.
    /// See [`Self`] for the checks left to the caller.
    pub fn verify_signature(
        &self,
        response: &VerifyForeignTransactionResponseV2,
        // TODO(#2232): don't use interface API types for public keys
        public_key: &PublicKey,
    ) -> Result<VerifiedForeignTxResponseV2, VerifyForeignChainError> {
        let verified = self.verify_signed_outcome(response, public_key)?;
        match verified.outcome {
            ForeignTxVerificationOutcome::Verified {} => Ok(verified),
            ForeignTxVerificationOutcome::Negative { verdict } => {
                Err(VerifyForeignChainError::NegativeOutcome { verdict })
            }
            ForeignTxVerificationOutcome::Inconclusive {} => {
                Err(VerifyForeignChainError::InconclusiveOutcome)
            }
        }
    }

    /// Succeeds for any outcome the network signed as an answer to the request under
    /// `public_key`. See [`Self`] for the checks left to the caller.
    pub fn verify_signed_outcome(
        &self,
        response: &VerifyForeignTransactionResponseV2,
        // TODO(#2232): don't use interface API types for public keys
        public_key: &PublicKey,
    ) -> Result<VerifiedForeignTxResponseV2, VerifyForeignChainError> {
        let expected_values_hash = self
            .request
            .expected_values_hash()
            .map_err(|_| VerifyForeignChainError::FailedToComputeMsgHash)?;
        let expected_payload_hash = ForeignTxSignPayload::V2(ForeignTxSignPayloadV2 {
            request: self.request.request.clone(),
            expected_values_hash,
            request_block_height: response.request_block_height,
            yield_id: response.yield_id,
            outcome: response.outcome.clone(),
        })
        .compute_msg_hash()
        .map_err(|_| VerifyForeignChainError::FailedToComputeMsgHash)?;

        verify_signed_payload_hash(
            expected_payload_hash,
            &response.payload_hash,
            &response.signature,
            public_key,
        )?;

        Ok(VerifiedForeignTxResponseV2 {
            request_block_height: response.request_block_height,
            yield_id: response.yield_id,
            outcome: response.outcome.clone(),
        })
    }
}

impl VerifiedForeignTxResponseV2 {
    /// The block the request was made in. The network checks the foreign chain only while the
    /// request is pending, and the request is pending from this block on.
    pub fn request_block_height(&self) -> BlockHeight {
        self.request_block_height
    }

    /// The yield the contract assigned to the request this response answers.
    pub fn yield_id(&self) -> YieldId {
        self.yield_id
    }

    /// Only [`ForeignTxVerificationOutcome::Verified`] means the extracted values equal the
    /// expected ones.
    pub fn outcome(&self) -> &ForeignTxVerificationOutcome {
        &self.outcome
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use near_mpc_contract_interface::types::{
        DomainId, Ed25519PublicKey, Ed25519Signature, EvmExtractedValue, EvmExtractor, EvmFinality,
        EvmRpcRequest, EvmTxId, ExtractedValue, ForeignChainRpcRequest,
        ForeignTxVerificationNegativeVerdict, Hash256, K256Signature, Secp256k1PublicKey,
        SignatureResponse,
    };
    use rstest::rstest;
    use std::assert_matches;

    struct SignedFields {
        request_block_height: BlockHeight,
        yield_id: YieldId,
        outcome: ForeignTxVerificationOutcome,
    }

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    fn public_key() -> PublicKey {
        PublicKey::Ed25519(Ed25519PublicKey::from(&signing_key().verifying_key()))
    }

    fn secp256k1_signing_key() -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_bytes(&[7; 32].into()).unwrap()
    }

    fn secp256k1_public_key() -> PublicKey {
        let public_key = k256::PublicKey::from(secp256k1_signing_key().verifying_key());
        PublicKey::Secp256k1(Secp256k1PublicKey::from(&public_key))
    }

    fn with_secp256k1_signature(
        response: VerifyForeignTransactionResponseV2,
    ) -> VerifyForeignTransactionResponseV2 {
        let (signature, recovery_id) = secp256k1_signing_key()
            .sign_prehash_recoverable(response.payload_hash.as_slice())
            .unwrap();
        VerifyForeignTransactionResponseV2 {
            signature: SignatureResponse::Secp256k1(K256Signature::from_ecdsa_recoverable(
                &signature,
                recovery_id,
            )),
            ..response
        }
    }

    fn request() -> VerifyForeignTransactionRequestV2 {
        VerifyForeignTransactionRequestV2 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0xab; 32]),
                extractors: [EvmExtractor::BlockHash].into(),
                finality: EvmFinality::Finalized,
            }),
            domain_id: DomainId(0),
            expected_values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
            )],
        }
    }

    fn signed_fields() -> SignedFields {
        SignedFields {
            request_block_height: BlockHeight::new(1_000),
            yield_id: YieldId([0xcd; 32]),
            outcome: ForeignTxVerificationOutcome::Verified {},
        }
    }

    fn signed_response(
        request: &VerifyForeignTransactionRequestV2,
        fields: SignedFields,
    ) -> VerifyForeignTransactionResponseV2 {
        let payload_hash = ForeignTxSignPayload::V2(ForeignTxSignPayloadV2 {
            request: request.request.clone(),
            expected_values_hash: request.expected_values_hash().unwrap(),
            request_block_height: fields.request_block_height,
            yield_id: fields.yield_id,
            outcome: fields.outcome.clone(),
        })
        .compute_msg_hash()
        .unwrap();
        let signature = signing_key().sign(payload_hash.as_slice());
        VerifyForeignTransactionResponseV2 {
            payload_hash,
            signature: SignatureResponse::Ed25519 {
                signature: Ed25519Signature::from(signature),
            },
            request_block_height: fields.request_block_height,
            yield_id: fields.yield_id,
            outcome: fields.outcome,
        }
    }

    fn negative(verdict: ForeignTxVerificationNegativeVerdict) -> ForeignTxVerificationOutcome {
        ForeignTxVerificationOutcome::Negative { verdict }
    }

    #[rstest]
    #[case::verified(ForeignTxVerificationOutcome::Verified {})]
    #[case::transaction_failed(negative(ForeignTxVerificationNegativeVerdict::TransactionFailed))]
    #[case::log_index_out_of_bounds(negative(
        ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds
    ))]
    #[case::transaction_not_found(negative(
        ForeignTxVerificationNegativeVerdict::TransactionNotFound
    ))]
    #[case::account_not_found(negative(ForeignTxVerificationNegativeVerdict::AccountNotFound))]
    #[case::non_canonical_block(negative(ForeignTxVerificationNegativeVerdict::NonCanonicalBlock))]
    #[case::values_mismatch(negative(ForeignTxVerificationNegativeVerdict::ValuesMismatch))]
    #[case::inconclusive(ForeignTxVerificationOutcome::Inconclusive {})]
    fn verify_signed_outcome__should_accept_a_response_to_its_request(
        #[case] outcome: ForeignTxVerificationOutcome,
    ) {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let fields = SignedFields {
            outcome: outcome.clone(),
            ..signed_fields()
        };
        let response = signed_response(&request(), fields);

        // When
        let verified = verifier
            .verify_signed_outcome(&response, &public_key())
            .unwrap();

        // Then
        assert_eq!(verified.outcome(), &outcome);
        assert_eq!(verified.yield_id(), signed_fields().yield_id);
        assert_eq!(
            verified.request_block_height(),
            signed_fields().request_block_height
        );
    }

    #[test]
    fn verify_signature__should_accept_a_verified_outcome() {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let response = signed_response(&request(), signed_fields());

        // When
        let verified = verifier.verify_signature(&response, &public_key()).unwrap();

        // Then
        assert_eq!(
            verified.outcome(),
            &ForeignTxVerificationOutcome::Verified {}
        );
    }

    #[rstest]
    #[case::transaction_failed(ForeignTxVerificationNegativeVerdict::TransactionFailed)]
    #[case::log_index_out_of_bounds(ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds)]
    #[case::transaction_not_found(ForeignTxVerificationNegativeVerdict::TransactionNotFound)]
    #[case::account_not_found(ForeignTxVerificationNegativeVerdict::AccountNotFound)]
    #[case::non_canonical_block(ForeignTxVerificationNegativeVerdict::NonCanonicalBlock)]
    #[case::values_mismatch(ForeignTxVerificationNegativeVerdict::ValuesMismatch)]
    fn verify_signature__should_reject_a_signed_negative_outcome(
        #[case] verdict: ForeignTxVerificationNegativeVerdict,
    ) {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let fields = SignedFields {
            outcome: negative(verdict),
            ..signed_fields()
        };
        let response = signed_response(&request(), fields);

        // When
        let result = verifier.verify_signature(&response, &public_key());

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::NegativeOutcome { verdict: rejected }) if rejected == verdict
        );
    }

    #[test]
    fn verify_signature__should_reject_a_signed_inconclusive_outcome() {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let fields = SignedFields {
            outcome: ForeignTxVerificationOutcome::Inconclusive {},
            ..signed_fields()
        };
        let response = signed_response(&request(), fields);

        // When
        let result = verifier.verify_signature(&response, &public_key());

        // Then
        assert_matches!(result, Err(VerifyForeignChainError::InconclusiveOutcome));
    }

    fn other_request() -> VerifyForeignTransactionRequestV2 {
        VerifyForeignTransactionRequestV2 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x01; 32]),
                extractors: [EvmExtractor::BlockHash].into(),
                finality: EvmFinality::Finalized,
            }),
            ..request()
        }
    }

    fn other_expected_values() -> VerifyForeignTransactionRequestV2 {
        VerifyForeignTransactionRequestV2 {
            expected_values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0x02; 32])),
            )],
            ..request()
        }
    }

    #[rstest]
    #[case::other_request(other_request())]
    #[case::other_expected_values(other_expected_values())]
    fn verify_signature__should_reject_a_response_to_another_request(
        #[case] verified_request: VerifyForeignTransactionRequestV2,
    ) {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(verified_request);
        let response = signed_response(&request(), signed_fields());

        // When
        let result = verifier.verify_signature(&response, &public_key());

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::IncorrectPayloadSigned { .. })
        );
    }

    #[rstest]
    #[case::other_yield_id(SignedFields {
        yield_id: YieldId([0x02; 32]),
        ..signed_fields()
    })]
    #[case::other_block_height(SignedFields {
        request_block_height: BlockHeight::new(1_001),
        ..signed_fields()
    })]
    #[case::other_outcome(SignedFields {
        outcome: negative(ForeignTxVerificationNegativeVerdict::TransactionNotFound),
        ..signed_fields()
    })]
    fn verify_signature__should_reject_a_signature_over_other_fields(
        #[case] altered_fields: SignedFields,
    ) {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let signed = signed_response(&request(), signed_fields());
        let response = VerifyForeignTransactionResponseV2 {
            signature: signed.signature,
            ..signed_response(&request(), altered_fields)
        };

        // When
        let result = verifier.verify_signature(&response, &public_key());

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::SignatureVerificationFailed)
        );
    }

    #[rstest]
    #[case::other_yield_id(SignedFields {
        yield_id: YieldId([0x02; 32]),
        ..signed_fields()
    })]
    #[case::other_block_height(SignedFields {
        request_block_height: BlockHeight::new(1_001),
        ..signed_fields()
    })]
    #[case::other_outcome(SignedFields {
        outcome: negative(ForeignTxVerificationNegativeVerdict::TransactionNotFound),
        ..signed_fields()
    })]
    fn verify_signed_outcome__should_reject_altered_fields_under_the_original_payload_hash(
        #[case] altered_fields: SignedFields,
    ) {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let response = VerifyForeignTransactionResponseV2 {
            request_block_height: altered_fields.request_block_height,
            yield_id: altered_fields.yield_id,
            outcome: altered_fields.outcome,
            ..signed_response(&request(), signed_fields())
        };

        // When
        let result = verifier.verify_signed_outcome(&response, &public_key());

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::IncorrectPayloadSigned { .. })
        );
    }

    #[test]
    fn verify_signature__should_reject_a_signature_under_another_key() {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let response = signed_response(&request(), signed_fields());
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key();

        // When
        let result = verifier.verify_signature(
            &response,
            &PublicKey::Ed25519(Ed25519PublicKey::from(&other_key)),
        );

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn verify_signature__should_accept_a_secp256k1_signature() {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let response = with_secp256k1_signature(signed_response(&request(), signed_fields()));

        // When
        let verified = verifier
            .verify_signature(&response, &secp256k1_public_key())
            .unwrap();

        // Then
        assert_eq!(verified.outcome(), &signed_fields().outcome);
    }

    #[test]
    fn verify_signature__should_reject_a_signature_of_another_scheme() {
        // Given
        let verifier = ForeignChainSignatureVerifierV2::new(request());
        let response = with_secp256k1_signature(signed_response(&request(), signed_fields()));

        // When
        let result = verifier.verify_signature(&response, &public_key());

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::UnexpectedSignatureScheme)
        );
    }
}
