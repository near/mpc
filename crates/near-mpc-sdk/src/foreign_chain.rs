use crate::sign::NotSet;
pub use contract_interface::method_names::VERIFY_FOREIGN_TRANSACTION as VERIFY_FOREIGN_TRANSACTION_METHOD_NAME;

pub mod abstract_chain;
pub mod bitcoin;
pub mod starknet;

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

pub enum VerifyForeignChainResponse {
    FailedToComputeMsgHash,
    IncorrectPayloadSigned { got: Hash256, expected: Hash256 },
}

impl ForeignChainSignatureVerifier {
    pub fn verify_signature(
        self,
        response: &VerifyForeignTransactionResponse,
        // TODO(#2232): don't use interface API types for public keys
        _public_key: &PublicKey,
    ) -> Result<(), VerifyForeignChainResponse> {
        let expected_payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: self.request,
            values: self.expected_extracted_values,
        });

        let expected_payload_hash = expected_payload
            .compute_msg_hash()
            .map_err(|_| VerifyForeignChainResponse::FailedToComputeMsgHash)?;

        let payload_is_correct = expected_payload_hash == response.payload_hash;

        if !payload_is_correct {
            return Err(VerifyForeignChainResponse::IncorrectPayloadSigned {
                got: response.payload_hash.clone(),
                expected: expected_payload_hash,
            });
        }

        // TODO(#2246): do signature verification check on the `response.signature`
        // Not having this check in place is "okay", if the response comes directly from
        // the MPC contract, since the contract already does this verification.
        Ok(())
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
