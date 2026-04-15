use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(target_arch = "wasm32"))]
use serde::Deserialize;
use serde::Serialize;

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
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Deserialize))]
pub struct Metrics {
    pub sign_with_v1_payload_count: u64,
    pub sign_with_v2_payload_count: u64,
}
