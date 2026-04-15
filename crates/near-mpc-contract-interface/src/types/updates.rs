use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(target_arch = "wasm32"))]
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

type Sha256Digest = [u8; 32];

#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Deserialize))]
pub struct ProposedUpdates {
    pub votes: BTreeMap<AccountId, u64>,
    pub updates: BTreeMap<u64, UpdateHash>,
}

/// An update hash
#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Deserialize))]
pub enum UpdateHash {
    Code(Sha256Digest),
    Config(Sha256Digest),
}
