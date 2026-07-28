use crate::types::Config;
use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type Sha256Digest = [u8; 32];

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
    pub votes: BTreeMap<AccountId, u64>,
    pub updates: BTreeMap<u64, UpdateHash>,
}

/// An update hash
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
    Code(Sha256Digest),
    Config(Sha256Digest),
}

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

/// Sizing a proposal's payload failed.
#[derive(Debug, thiserror::Error)]
pub enum PayloadBytesError {
    #[error("the config does not serialize to JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("the payload exceeds u128::MAX bytes")]
    Overflow,
}
