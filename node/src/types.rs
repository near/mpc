use mpc_contract::primitives::domain::DomainId;
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
