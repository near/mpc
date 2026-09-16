use crate::sign::NotSet;
use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::BoundedVecOutOfBounds;
pub use near_mpc_contract_interface::method_names::VERIFY_FOREIGN_TRANSACTION as VERIFY_FOREIGN_TRANSACTION_METHOD_NAME;

pub mod abstract_chain;
pub mod adi;
pub mod arbitrum;
pub mod avalanche;
pub mod base;
pub mod bitcoin;
pub mod bnb;
pub mod ethereum;
pub mod evm;
pub mod fogo;
pub mod hyper_evm;
pub mod polygon;
pub mod solana;
pub mod starknet;
pub mod svm;
pub mod validation;

use near_mpc_contract_interface::types::PublicKey;
// response types
pub use near_mpc_contract_interface::types::{
    ForeignTxNegativeVerdict, Hash256, SignatureResponse, VerifyForeignTransactionResponse,
};

// raw request arg type
pub use near_mpc_contract_interface::types::{
    BlockConfirmations, DomainId, ExtractedValue, ForeignChain, ForeignChainRpcRequest,
    ForeignTxPayloadVersion, ForeignTxSignPayload, ForeignTxSignPayloadV1,
    MAX_EXTRACTORS_PER_REQUEST, VerifyForeignTransactionRequestArgs,
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, BorshSerialize, BorshDeserialize)]
pub struct ForeignChainSignatureVerifier {
    expected_extracted_values: Vec<ExtractedValue>,
    request: ForeignChainRpcRequest,
}

#[derive(Debug)]
pub enum VerifyForeignChainError {
    FailedToComputeMsgHash,
    IncorrectPayloadSigned { got: Hash256, expected: Hash256 },
    UnexpectedSignatureScheme,
    SignatureVerificationFailed,
    NegativeVerdict(ForeignTxNegativeVerdict),
}

impl ForeignChainSignatureVerifier {
    pub fn verify_signature(
        self,
        response: &VerifyForeignTransactionResponse,
        // TODO(#2232): don't use interface API types for public keys
        public_key: &PublicKey,
    ) -> Result<(), VerifyForeignChainError> {
        let payload_hash = match &response.negative_verdict {
            Some(verdict) => {
                ForeignTxSignPayload::negative_verdict(self.request, *verdict).compute_msg_hash()
            }
            None => expected_payload_hash(self.request, self.expected_extracted_values),
        }
        .map_err(|_| VerifyForeignChainError::FailedToComputeMsgHash)?;

        if payload_hash != response.payload_hash {
            return Err(VerifyForeignChainError::IncorrectPayloadSigned {
                got: response.payload_hash.clone(),
                expected: payload_hash,
            });
        }
        let verification_result = match (public_key, &response.signature) {
            (
                PublicKey::Secp256k1(secp256k1_public_key),
                SignatureResponse::Secp256k1(k256_signature),
            ) => near_mpc_signature_verifier::verify_ecdsa_signature(
                k256_signature,
                &payload_hash,
                secp256k1_public_key,
            ),
            (PublicKey::Ed25519(ed25519_public_key), SignatureResponse::Ed25519 { signature }) => {
                near_mpc_signature_verifier::verify_eddsa_signature(
                    signature,
                    payload_hash.as_slice(),
                    ed25519_public_key,
                )
            }
            // TODO(#2234): improve types so these errors can't happen
            (PublicKey::Bls12381(_bls12381_g2_public_key), _) => {
                return Err(VerifyForeignChainError::UnexpectedSignatureScheme);
            }
            _ => return Err(VerifyForeignChainError::UnexpectedSignatureScheme),
        };

        verification_result.map_err(|_| VerifyForeignChainError::SignatureVerificationFailed)?;

        match &response.negative_verdict {
            Some(verdict) => Err(VerifyForeignChainError::NegativeVerdict(*verdict)),
            None => Ok(()),
        }
    }
}

pub const DEFAULT_PAYLOAD_VERSION: ForeignTxPayloadVersion = ForeignTxPayloadVersion::V1;

#[derive(Debug, Clone)]
pub struct ForeignChainRequestBuilder<Request, DomainId> {
    request: Request,
    domain_id: DomainId,
}

impl<Request> ForeignChainRequestBuilder<Request, NotSet>
where
    Request: TryInto<ForeignChainRpcRequestWithExpectations, Error = BoundedVecOutOfBounds>,
{
    pub fn with_domain_id(
        self,
        domain_id: impl Into<DomainId>,
    ) -> ForeignChainRequestBuilder<Request, DomainId> {
        ForeignChainRequestBuilder {
            request: self.request,
            domain_id: domain_id.into(),
        }
    }
}

impl<Request> ForeignChainRequestBuilder<Request, DomainId>
where
    Request: TryInto<ForeignChainRpcRequestWithExpectations, Error = BoundedVecOutOfBounds>,
{
    /// Errors if the request holds more than [`MAX_EXTRACTORS_PER_REQUEST`] extractors, or
    /// if borsh serializing the expected payload for hashing fails.
    pub fn build(
        self,
    ) -> Result<
        (
            ForeignChainSignatureVerifier,
            VerifyForeignTransactionRequestArgs,
        ),
        BuildRequestError,
    > {
        let ForeignChainRpcRequestWithExpectations {
            request,
            expected_values,
        } = self.request.try_into()?;

        let verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: expected_values,
            request: request.clone(),
        };

        let expected_payload_hash = expected_payload_hash(
            verifier.request.clone(),
            verifier.expected_extracted_values.clone(),
        )?;

        let request_args = VerifyForeignTransactionRequestArgs {
            request,
            domain_id: self.domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
            expected_payload_hash: Some(expected_payload_hash),
        };

        Ok((verifier, request_args))
    }
}

fn expected_payload_hash(
    request: ForeignChainRpcRequest,
    expected_values: Vec<ExtractedValue>,
) -> std::io::Result<Hash256> {
    ForeignTxSignPayload::new(DEFAULT_PAYLOAD_VERSION, request, expected_values).compute_msg_hash()
}

pub struct ForeignChainRpcRequestWithExpectations {
    request: ForeignChainRpcRequest,
    expected_values: Vec<ExtractedValue>,
}

#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum BuildRequestError {
    #[display("the request holds too many extractors: {_0}")]
    TooManyExtractors(BoundedVecOutOfBounds),
    #[display("failed to hash the expected payload: {_0}")]
    PayloadHash(std::io::Error),
}

impl std::error::Error for BuildRequestError {}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{
        EvmExtractedValue, EvmExtractor, EvmFinality, EvmRpcRequest, EvmTxId, K256Signature,
        Secp256k1PublicKey,
    };

    use super::*;

    fn ethereum_request() -> ForeignChainRpcRequest {
        ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0xab; 32]),
            extractors: [EvmExtractor::BlockHash].into(),
            finality: EvmFinality::Finalized,
        })
    }

    fn verifier_for(request: ForeignChainRpcRequest) -> ForeignChainSignatureVerifier {
        ForeignChainSignatureVerifier {
            expected_extracted_values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
            )],
            request,
        }
    }

    fn signing_key() -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_bytes(&[42u8; 32].into()).unwrap()
    }

    fn sign_payload_hash(
        signing_key: &k256::ecdsa::SigningKey,
        payload_hash: &Hash256,
    ) -> SignatureResponse {
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&payload_hash.0)
            .unwrap();
        SignatureResponse::Secp256k1(K256Signature::from_ecdsa_recoverable(
            &signature,
            recovery_id,
        ))
    }

    fn public_key_of(signing_key: &k256::ecdsa::SigningKey) -> PublicKey {
        PublicKey::Secp256k1(Secp256k1PublicKey::from(&k256::PublicKey::from(
            signing_key.verifying_key(),
        )))
    }

    #[test]
    fn foreign_chain_signature_verifier__should_return_negative_verdict_for_well_signed_negative_response()
     {
        // Given
        let signing_key = signing_key();
        let request = ethereum_request();
        let payload_hash = ForeignTxSignPayload::negative_verdict(
            request.clone(),
            ForeignTxNegativeVerdict::TransactionNotFound,
        )
        .compute_msg_hash()
        .unwrap();
        let signature = sign_payload_hash(&signing_key, &payload_hash);
        let response = VerifyForeignTransactionResponse {
            payload_hash,
            signature,
            negative_verdict: Some(ForeignTxNegativeVerdict::TransactionNotFound),
        };

        // When
        let result =
            verifier_for(request).verify_signature(&response, &public_key_of(&signing_key));

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::NegativeVerdict(
                ForeignTxNegativeVerdict::TransactionNotFound
            ))
        );
    }

    #[test]
    fn foreign_chain_signature_verifier__should_reject_negative_verdict_when_payload_hash_mismatches()
     {
        // Given
        let signing_key = signing_key();
        let request = ethereum_request();
        let verdict = ForeignTxNegativeVerdict::TransactionNotFound;
        let wrong_payload_hash = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.clone(),
            values: vec![],
        })
        .compute_msg_hash()
        .unwrap();
        let expected_negative_hash =
            ForeignTxSignPayload::negative_verdict(request.clone(), verdict)
                .compute_msg_hash()
                .unwrap();
        let signature = sign_payload_hash(&signing_key, &wrong_payload_hash);
        let response = VerifyForeignTransactionResponse {
            payload_hash: wrong_payload_hash.clone(),
            signature,
            negative_verdict: Some(verdict),
        };

        // When
        let result =
            verifier_for(request).verify_signature(&response, &public_key_of(&signing_key));

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::IncorrectPayloadSigned {
                got,
                expected
            }) if got == wrong_payload_hash && expected == expected_negative_hash
        );
    }

    #[test]
    fn foreign_chain_signature_verifier__should_reject_negative_verdict_with_invalid_signature() {
        // Given
        let signing_key = signing_key();
        let wrong_signing_key = k256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let request = ethereum_request();
        let payload_hash = ForeignTxSignPayload::negative_verdict(
            request.clone(),
            ForeignTxNegativeVerdict::TransactionNotFound,
        )
        .compute_msg_hash()
        .unwrap();
        let signature = sign_payload_hash(&wrong_signing_key, &payload_hash);
        let response = VerifyForeignTransactionResponse {
            payload_hash,
            signature,
            negative_verdict: Some(ForeignTxNegativeVerdict::TransactionNotFound),
        };

        // When
        let result =
            verifier_for(request).verify_signature(&response, &public_key_of(&signing_key));

        // Then
        assert_matches!(
            result,
            Err(VerifyForeignChainError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn foreign_chain_signature_verifier__should_accept_well_signed_success_response() {
        // Given
        let signing_key = signing_key();
        let request = ethereum_request();
        let payload_hash = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.clone(),
            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
            )],
        })
        .compute_msg_hash()
        .unwrap();
        let signature = sign_payload_hash(&signing_key, &payload_hash);
        let response = VerifyForeignTransactionResponse {
            payload_hash,
            signature,
            negative_verdict: None,
        };

        // When
        let result =
            verifier_for(request).verify_signature(&response, &public_key_of(&signing_key));

        // Then
        assert_matches!(result, Ok(()));
    }
}
