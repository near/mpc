use crate::sign::NotSet;
use borsh::{BorshDeserialize, BorshSerialize};
pub use near_mpc_contract_interface::method_names::VERIFY_FOREIGN_TRANSACTION as VERIFY_FOREIGN_TRANSACTION_METHOD_NAME;

pub mod abstract_chain;
pub mod base;
pub mod bitcoin;
pub mod bnb;
pub mod evm;
pub mod starknet;

use near_mpc_contract_interface::types::PublicKey;
// response types
pub use near_mpc_contract_interface::types::{
    Hash256, SignatureResponse, VerifyForeignTransactionResponse,
};

// raw request arg type
pub use near_mpc_contract_interface::types::{
    BlockConfirmations, DomainId, ExtractedValue, ForeignChain, ForeignChainRpcRequest,
    ForeignTxPayloadVersion, ForeignTxSignPayload, ForeignTxSignPayloadV1,
    VerifyForeignTransactionRequestArgs,
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, BorshSerialize, BorshDeserialize)]
pub struct ForeignChainSignatureVerifier {
    expected_extracted_values: Vec<ExtractedValue>,
    request: ForeignChainRpcRequest,
}

pub enum VerifyForeignChainError {
    FailedToComputeMsgHash,
    IncorrectPayloadSigned { got: Hash256, expected: Hash256 },
    UnexpectedSignatureScheme,
    SignatureVerificationFailed,
}

impl ForeignChainSignatureVerifier {
    pub fn verify_signature(
        self,
        response: &VerifyForeignTransactionResponse,
        // TODO(#2232): don't use interface API types for public keys
        public_key: &PublicKey,
    ) -> Result<(), VerifyForeignChainError> {
        let expected_payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: self.request,
            values: self.expected_extracted_values,
        });

        let expected_payload_hash = expected_payload
            .compute_msg_hash()
            .map_err(|_| VerifyForeignChainError::FailedToComputeMsgHash)?;

        let payload_is_correct = expected_payload_hash == response.payload_hash;

        if !payload_is_correct {
            return Err(VerifyForeignChainError::IncorrectPayloadSigned {
                got: response.payload_hash.clone(),
                expected: expected_payload_hash,
            });
        }
        let verification_result = match (public_key, &response.signature) {
            (
                PublicKey::Secp256k1(secp256k1_public_key),
                SignatureResponse::Secp256k1(k256_signature),
            ) => near_mpc_signature_verifier::verify_ecdsa_signature(
                k256_signature,
                &expected_payload_hash,
                secp256k1_public_key,
            ),
            (PublicKey::Ed25519(ed25519_public_key), SignatureResponse::Ed25519 { signature }) => {
                near_mpc_signature_verifier::verify_eddsa_signature(
                    signature,
                    expected_payload_hash.as_slice(),
                    ed25519_public_key,
                )
            }
            // TODO(#2234): improve types so these errors can't happen
            (PublicKey::Bls12381(_bls12381_g2_public_key), _) => {
                return Err(VerifyForeignChainError::UnexpectedSignatureScheme);
            }
            _ => return Err(VerifyForeignChainError::UnexpectedSignatureScheme),
        };

        verification_result.map_err(|_| VerifyForeignChainError::SignatureVerificationFailed)
    }
}

pub const DEFAULT_PAYLOAD_VERSION: ForeignTxPayloadVersion = ForeignTxPayloadVersion::V1;

#[derive(Debug, Clone)]
pub struct ForeignChainRequestBuilder<Request, DomainId> {
    request: Request,
    domain_id: DomainId,
}

impl<Request: Into<ForeignChainRpcRequestWithExpectations>>
    ForeignChainRequestBuilder<Request, NotSet>
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

impl<Request: Into<ForeignChainRpcRequestWithExpectations>>
    ForeignChainRequestBuilder<Request, DomainId>
{
    pub fn build(
        self,
    ) -> (
        ForeignChainSignatureVerifier,
        VerifyForeignTransactionRequestArgs,
    ) {
        let ForeignChainRpcRequestWithExpectations {
            request,
            expected_values,
        } = self.request.into();

        let verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: expected_values,
            request: request.clone(),
        };

        let request_args = VerifyForeignTransactionRequestArgs {
            request,
            domain_id: self.domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
        };

        (verifier, request_args)
    }
}

pub struct ForeignChainRpcRequestWithExpectations {
    request: ForeignChainRpcRequest,
    expected_values: Vec<ExtractedValue>,
}
