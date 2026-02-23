use bounded_collections::{BoundedVec, hex_serde};
use serde::{Deserialize, Serialize};

use crate::types::DomainId;

const ECDSA_PAYLOAD_SIZE_BYTES: usize = 32;
const EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES: usize = 32;
const EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES: usize = 1232;

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
