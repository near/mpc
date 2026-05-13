use std::fmt;

use mpc_primitives::domain::DomainId;
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::types::{Payload, Tweak};
use near_mpc_crypto_types::kdf::derive_tweak;
use serde::{Deserialize, Serialize};

use near_mpc_contract_interface::types as dtos;

use crate::{
    indexer::handler::{
        CKDRequestFromChain, SignatureRequestFromChain, VerifyForeignTxRequestFromChain,
    },
    requests::recent_blocks_tracker::BlockViewLite,
};

pub(crate) struct RequestsUpdate<T> {
    pub(crate) block: BlockViewLite,
    pub(crate) requests: Vec<T>,
    pub(crate) completed_requests: Vec<RequestId>,
}

impl<T> RequestsUpdate<T> {
    pub(crate) fn from_chain<U>(
        block: &BlockViewLite,
        new_requests: Vec<U>,
        completed_requests: Vec<RequestId>,
    ) -> RequestsUpdate<T>
    where
        T: FromChain<U>,
    {
        let requests = new_requests
            .into_iter()
            .map(|request_from_chain| T::from_chain(request_from_chain, block))
            .collect::<Vec<_>>();

        RequestsUpdate {
            block: block.clone(),
            requests,
            completed_requests,
        }
    }
}

pub enum RequestType {
    Signature,
    CKD,
    VerifyForeignTx,
}

pub type RequestId = CryptoHash;

/// The trait that defines common functionality of MPC requests:
/// currently CKD and signatures
pub trait Request {
    fn get_id(&self) -> RequestId;
    fn get_receipt_id(&self) -> CryptoHash;
    fn get_entropy(&self) -> [u8; 32];
    fn get_timestamp_nanosec(&self) -> u64;
    fn get_domain_id(&self) -> DomainId;
    fn get_type() -> RequestType;
}

/// A request paired with the contract-minted `request_id` extracted from the
/// `MPC_REQUEST_ID:` log on its originating receipt (#3184). The wrapper
/// lives at the queue and respond boundary so that the inner request types
/// (`SignatureRequest`, `CKDRequest`, `VerifyForeignTxRequest`) stay
/// independent of the yield handle — they describe "what to compute", the
/// wrapper carries "which specific yield this is".
///
/// `None` means we don't have a contract id for this request: typically a
/// pre-#3184 contract that doesn't emit the log, or a yield that's only
/// resolvable through the legacy fallback path. `respond*` callers thread
/// the value straight through into `ChainSignatureRespondArgs::request_id`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IndexedRequest<T> {
    pub request: T,
    pub request_id: Option<CryptoHash>,
}

impl<T: Request> Request for IndexedRequest<T> {
    fn get_id(&self) -> RequestId {
        self.request.get_id()
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.request.get_receipt_id()
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.request.get_entropy()
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.request.get_timestamp_nanosec()
    }

    fn get_domain_id(&self) -> DomainId {
        self.request.get_domain_id()
    }

    fn get_type() -> RequestType {
        T::get_type()
    }
}

pub type CKDId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CKDRequest {
    /// The unique ID that identifies the ckd, and can also uniquely identify the response.
    pub id: CKDId,
    /// The receipt that generated the ckd request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub app_public_key: dtos::CKDAppPublicKey,
    pub app_id: dtos::CkdAppId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain_id: DomainId,
}

pub(crate) trait FromChain<T> {
    fn from_chain(chain_value: T, block: &BlockViewLite) -> Self;
}

impl FromChain<CKDRequestFromChain> for IndexedRequest<CKDRequest> {
    fn from_chain(chain_value: CKDRequestFromChain, block: &BlockViewLite) -> Self {
        let CKDRequestFromChain {
            ckd_id,
            receipt_id,
            request,
            request_id,
        } = chain_value;
        IndexedRequest {
            request: CKDRequest {
                id: ckd_id,
                receipt_id,
                app_public_key: request.app_public_key,
                app_id: request.app_id,
                entropy: block.entropy.clone().into(),
                timestamp_nanosec: block.timestamp_nanosec,
                domain_id: request.domain_id,
            },
            request_id,
        }
    }
}

pub type SignatureId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureRequest {
    /// The unique ID that identifies the signature, and can also uniquely identify the response.
    pub id: SignatureId,
    /// The receipt that generated the signature request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub payload: Payload,
    pub tweak: Tweak,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain: DomainId,
}

impl FromChain<SignatureRequestFromChain> for IndexedRequest<SignatureRequest> {
    fn from_chain(chain_value: SignatureRequestFromChain, block: &BlockViewLite) -> Self {
        let SignatureRequestFromChain {
            signature_id,
            receipt_id,
            request,
            predecessor_id,
            request_id,
        } = chain_value;
        IndexedRequest {
            request: SignatureRequest {
                id: signature_id,
                receipt_id,
                payload: request.payload,
                tweak: derive_tweak(&predecessor_id, &request.path),
                entropy: block.entropy.clone().into(),
                timestamp_nanosec: block.timestamp_nanosec,
                domain: request.domain_id,
            },
            request_id,
        }
    }
}

impl fmt::Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestType::Signature => write!(f, "signature"),
            RequestType::CKD => write!(f, "ckd"),
            RequestType::VerifyForeignTx => write!(f, "verify_foreign_tx"),
        }
    }
}

pub type VerifyForeignTxId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyForeignTxRequest {
    /// The unique ID that identifies the verify_foreign_tx, and can also uniquely identify the response.
    pub id: VerifyForeignTxId,
    /// The receipt that generated the verify_foreign_tx request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub request: dtos::ForeignChainRpcRequest,
    pub payload_version: dtos::ForeignTxPayloadVersion,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain_id: DomainId,
}

impl FromChain<VerifyForeignTxRequestFromChain> for IndexedRequest<VerifyForeignTxRequest> {
    fn from_chain(chain_value: VerifyForeignTxRequestFromChain, block: &BlockViewLite) -> Self {
        let VerifyForeignTxRequestFromChain {
            verify_foreign_tx_id,
            receipt_id,
            request,
            request_id,
        } = chain_value;
        IndexedRequest {
            request: VerifyForeignTxRequest {
                id: verify_foreign_tx_id,
                receipt_id,
                domain_id: request.domain_id,
                entropy: block.entropy.clone().into(),
                payload_version: request.payload_version,
                request: request.request,
                timestamp_nanosec: block.timestamp_nanosec,
            },
            request_id,
        }
    }
}

impl Request for CKDRequest {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain_id
    }

    fn get_type() -> RequestType {
        RequestType::CKD
    }
}

impl Request for SignatureRequest {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain
    }

    fn get_type() -> RequestType {
        RequestType::Signature
    }
}

impl Request for VerifyForeignTxRequest {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain_id
    }

    fn get_type() -> RequestType {
        RequestType::VerifyForeignTx
    }
}
