use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Metrics {
    pub sign_with_v1_payload_count: u64,
    pub sign_with_v2_payload_count: u64,
}
