use crate::types::Config;
use crate::types::foreign_chain::Hash256;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Payload of `submit_update`: new contract code or a new [`Config`]. Applied only while a
/// governance threshold of participants backs its [`UpdateHash`] via `vote_update`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum Update {
    Code(Vec<u8>),
    Config(Config),
}

/// Identifies an [`Update`] by content: the SHA-256 of the code bytes, or of the compact JSON
/// encoding of the config.
#[derive(
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
pub enum UpdateHash {
    Code(Hash256),
    Config(Hash256),
}
