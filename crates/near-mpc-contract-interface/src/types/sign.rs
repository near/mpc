use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::DomainId;

pub use near_mpc_crypto_types::{
    ECDSA_PAYLOAD_SIZE_BYTES, EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES,
    EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES, Payload,
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SignRequestArgs {
    pub path: String,
    pub payload_v2: Payload,
    pub domain_id: DomainId,
}
