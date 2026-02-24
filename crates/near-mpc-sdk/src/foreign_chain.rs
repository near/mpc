use crate::sign::NotSet;
use crate::verification::{check_ec_signature, check_ed_signature};
pub use contract_interface::method_names::VERIFY_FOREIGN_TRANSACTION as VERIFY_FOREIGN_TRANSACTION_METHOD_NAME;

pub mod abstract_chain;
pub mod bitcoin;

use contract_interface::types::PublicKey;
// response types
pub use contract_interface::types::{Hash256, SignatureResponse, VerifyForeignTransactionResponse};

// raw request arg type
pub use contract_interface::types::{
    BlockConfirmations, DomainId, ExtractedValue, ForeignChain, ForeignChainPolicy,
    ForeignChainRpcRequest, ForeignTxSignPayload, ForeignTxSignPayloadV1,
    VerifyForeignTransactionRequestArgs,
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ForeignChainSignatureVerifier {
    expected_extracted_values: Vec<ExtractedValue>,
    request: ForeignChainRpcRequest,
}

pub enum SignatureVerificationError {
    FailedToComputeMsgHash,
    IncorrectPayloadSigned { got: Hash256, expected: Hash256 },
    UnexpectedSignatureScheme,
    VerificationFailed,
}

impl ForeignChainSignatureVerifier {
    // todo, API type for public keys?
    pub fn verify_signature(
        self,
        response: &VerifyForeignTransactionResponse,
        public_key: &PublicKey,
    ) -> Result<(), SignatureVerificationError> {
        // check that payload matches the expected payload
        let expected_payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: self.request,
            values: self.expected_extracted_values,
        });

        let expected_payload_hash = expected_payload
            .compute_msg_hash()
            .map_err(|_| SignatureVerificationError::FailedToComputeMsgHash)?;

        let payload_is_correct = expected_payload_hash == response.payload_hash;
        if !payload_is_correct {
            return Err(SignatureVerificationError::IncorrectPayloadSigned {
                got: response.payload_hash.clone(),
                expected: expected_payload_hash,
            });
        }

        // check that signature is valid
        let verification_result = match (public_key, &response.signature) {
            (
                PublicKey::Secp256k1(secp256k1_public_key),
                SignatureResponse::Secp256k1(k256_signature),
            ) => check_ec_signature(k256_signature, &expected_payload_hash, secp256k1_public_key),
            (PublicKey::Ed25519(ed25519_public_key), SignatureResponse::Ed25519 { signature }) => {
                check_ed_signature(signature, &expected_payload_hash, ed25519_public_key)
            }
            // TODO: improve type system API so these errors can't happen
            (PublicKey::Bls12381(_bls12381_g2_public_key), _) => {
                return Err(SignatureVerificationError::UnexpectedSignatureScheme);
            }
            _ => return Err(SignatureVerificationError::UnexpectedSignatureScheme),
        };

        verification_result.map_err(|_| SignatureVerificationError::VerificationFailed)
    }
}

pub const DEFAULT_PAYLOAD_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct ForeignChainRequestBuilder<Request, DerivationPath, DomainId> {
    request: Request,
    derivation_path: DerivationPath,
    domain_id: DomainId,
    payload_version: u8,
}

impl Default for ForeignChainRequestBuilder<NotSet, NotSet, NotSet> {
    fn default() -> Self {
        Self::new()
    }
}

impl ForeignChainRequestBuilder<NotSet, NotSet, NotSet> {
    pub fn new() -> Self {
        Self {
            request: NotSet,
            derivation_path: NotSet,
            domain_id: NotSet,
            payload_version: DEFAULT_PAYLOAD_VERSION,
        }
    }
}

impl<Request: Into<ForeignChainRpcRequestWithExpectations>>
    ForeignChainRequestBuilder<Request, NotSet, NotSet>
{
    pub fn with_derivation_path(
        self,
        derivation_path: String,
    ) -> ForeignChainRequestBuilder<Request, String, NotSet> {
        ForeignChainRequestBuilder {
            request: self.request,
            derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }
}

impl<Request: Into<ForeignChainRpcRequestWithExpectations>>
    ForeignChainRequestBuilder<Request, String, NotSet>
{
    pub fn with_domain_id(
        self,
        domain_id: impl Into<DomainId>,
    ) -> ForeignChainRequestBuilder<Request, String, DomainId> {
        ForeignChainRequestBuilder {
            request: self.request,
            derivation_path: self.derivation_path,
            domain_id: domain_id.into(),
            payload_version: self.payload_version,
        }
    }
}

impl<Request: Into<ForeignChainRpcRequestWithExpectations>>
    ForeignChainRequestBuilder<Request, String, DomainId>
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
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        };

        (verifier, request_args)
    }
}

pub struct ForeignChainRpcRequestWithExpectations {
    request: ForeignChainRpcRequest,
    expected_values: Vec<ExtractedValue>,
}
