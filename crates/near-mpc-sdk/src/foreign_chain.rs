use crate::sign::NotSet;
pub use contract_interface::method_names::VERIFY_FOREIGN_TRANSACTION as VERIFY_FOREIGN_TRANSACTION_METHOD_NAME;

pub mod bitcoin;

// response types
pub use contract_interface::types::{Hash256, SignatureResponse, VerifyForeignTransactionResponse};

// raw request arg type
pub use contract_interface::types::{
    BlockConfirmations, DomainId, ExtractedValue, ForeignChain, ForeignChainPolicy,
    ForeignChainRpcRequest, ForeignTxSignPayload, ForeignTxSignPayloadV1,
    VerifyForeignTransactionRequestArgs,
};

#[allow(dead_code, reason = "TODO(#2130): Implement verification")]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ForeignChainSignatureVerifier {
    expected_extracted_values: Vec<ExtractedValue>,
    request: ForeignChainRpcRequest,
}

pub const DEFAULT_PAYLOAD_VERSION: u8 = 1;

pub trait RequestFinishedBuilding: Into<(ForeignChainRpcRequest, Vec<ExtractedValue>)> {}

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

impl<Request: RequestFinishedBuilding> ForeignChainRequestBuilder<Request, NotSet, NotSet> {
    pub fn with_derivation_path(
        self,
        derivation_path: String,
    ) -> ForeignChainRequestBuilder<Request, String, NotSet> {
        ForeignChainRequestBuilder {
            request: self.request,
            derivation_path,
            domain_id: NotSet,
            payload_version: self.payload_version,
        }
    }
}

impl<Request: RequestFinishedBuilding> ForeignChainRequestBuilder<Request, String, NotSet> {
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

impl<Request: RequestFinishedBuilding> ForeignChainRequestBuilder<Request, String, DomainId> {
    pub fn build(
        self,
    ) -> (
        ForeignChainSignatureVerifier,
        VerifyForeignTransactionRequestArgs,
    ) {
        let (request, expected_values) = self.request.into();

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
