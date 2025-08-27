use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::signature::{Payload, Tweak};
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize};

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
