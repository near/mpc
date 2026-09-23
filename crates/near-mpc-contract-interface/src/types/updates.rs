use crate::types::Config;
use crate::types::Hash256;
use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum Update {
    Code(Vec<u8>),
    Config(Config),
}

impl Update {
    pub fn payload_bytes(&self) -> Result<u128, PayloadBytesError> {
        let bytes = match self {
            Update::Code(code) => code.len(),
            Update::Config(config) => serde_json::to_vec(config)?.len(),
        };
        u128::try_from(bytes).map_err(|_| PayloadBytesError::Overflow)
    }
}

// TODO(#4513): drop once production runs the vote-then-submit API.
#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Deref,
    derive_more::From,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct UpdateId(pub u64);

// TODO(#4513): drop once production runs the vote-then-submit API.
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
    derive(schemars::JsonSchema)
)]
pub struct ProposedUpdates {
    pub votes: BTreeMap<AccountId, UpdateId>,
    pub updates: BTreeMap<UpdateId, UpdateHash>,
}

/// Identifies an [`Update`] by content.
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
    derive(schemars::JsonSchema)
)]
pub enum UpdateHash {
    Code(Hash256),
    Config(Hash256),
}

// TODO(#4513): drop once production runs the vote-then-submit API.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProposeUpdateArgs {
    pub code: Option<Vec<u8>>,
    pub config: Option<Config>,
}

impl ProposeUpdateArgs {
    pub fn payload_bytes(&self) -> Result<u128, PayloadBytesError> {
        let code_bytes = self.code.as_ref().map_or(0, |code| code.len());
        let config_bytes = self
            .config
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .map_or(0, |config| config.len());
        code_bytes
            .checked_add(config_bytes)
            .and_then(|payload_bytes| u128::try_from(payload_bytes).ok())
            .ok_or(PayloadBytesError::Overflow)
    }
}

/// Sizing a payload failed.
#[derive(Debug, thiserror::Error)]
pub enum PayloadBytesError {
    #[error("the config does not serialize to JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("the payload exceeds u128::MAX bytes")]
    Overflow,
}
