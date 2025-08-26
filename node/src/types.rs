use mpc_contract::primitives::{
    domain::DomainId,
    signature::{Payload, Tweak},
};
use near_indexer_primitives::CryptoHash;
use near_sdk::{AccountId, PublicKey};
use serde::{Deserialize, Serialize};

pub type CKDId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CKDRequest {
    /// The unique ID that identifies the ckd, and can also uniquely identify the response.
    pub id: CKDId,
    /// The receipt that generated the ckd request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub app_public_key: PublicKey,
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
