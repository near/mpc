use bounded_collections::{BoundedVec, hex_serde};
use serde::{Deserialize, Serialize};

use crate::types::DomainId;

pub const ECDSA_PAYLOAD_SIZE_BYTES: usize = 32;

pub const EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES: usize = 32;
// Transaction signatures for Solana is over the whole transaction payload,
// not the transaction hash. The max size for a solana transaction is 1232 bytes,
// to fit in a single UDP packet, hence the 1232 byte upper bounds.
pub const EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES: usize = 1232;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignRequestArgs {
    pub path: String,
    pub payload_v2: Payload,
    pub domain_id: DomainId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Payload {
    Ecdsa(
        #[serde(with = "hex_serde")]
        BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES>,
    ),
    Eddsa(
        #[serde(with = "hex_serde")]
        BoundedVec<u8, EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES, EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES>,
    ),
}
