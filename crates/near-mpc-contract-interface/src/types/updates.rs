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
    /// Bytes the proposal stores on chain: the code length or the config's
    /// JSON length. Sizes the deposit on both the contract and client side.
    pub fn payload_bytes(&self) -> Result<u128, serde_json::Error> {
        debug_assert!(
            !(self.code.is_some() && self.config.is_some()),
            "proposals carry code or config, not both"
        );
        Ok(self.code.as_ref().map_or(0, |code| code.len() as u128)
            + self
                .config
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()?
                .map_or(0, |config| config.len() as u128))
    }
}
