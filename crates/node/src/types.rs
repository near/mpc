use std::fmt;

use mpc_contract::primitives::{
    domain::DomainId,
    signature::{Payload, Tweak},
};
use near_indexer_primitives::CryptoHash;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};

use contract_interface::types as dtos;

pub enum RequestType {
    Signature,
    CKD,
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

pub type CKDId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CKDRequest {
    /// The unique ID that identifies the ckd, and can also uniquely identify the response.
    pub id: CKDId,
    /// The receipt that generated the ckd request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub app_id: AccountId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain_id: DomainId,
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

impl fmt::Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestType::Signature => write!(f, "signature"),
            RequestType::CKD => write!(f, "ckd"),
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
