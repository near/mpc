// applied on module since near proc macro is unable to apply the expect lint
#![expect(deprecated)]

use crate::types::config::Config;
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

#[deprecated(note = "legacy args for `propose_update`; the current contract uses \
            config-only `propose_config_update` plus the chunked-upload flow")]
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct LegacyProposeUpdateArgs {
    pub code: Option<Vec<u8>>,
    pub config: Option<Config>,
}
