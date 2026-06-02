use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Cryptographic threshold (`k`) for a distributed key: the minimum number of
/// participants that must collaborate to produce a signature.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Threshold(pub u64);

impl Threshold {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

/// Per-domain `t` in a t-of-n threshold scheme: shares needed to reconstruct
/// the secret. Distinct from the network-wide governance threshold.
#[derive(
    Clone,
    Copy,
    Debug,
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
#[serde(transparent)]
pub struct ReconstructionThreshold(u64);

impl ReconstructionThreshold {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn inner(self) -> u64 {
        self.0
    }
}

impl From<Threshold> for ReconstructionThreshold {
    fn from(value: Threshold) -> Self {
        Self(value.value())
    }
}
