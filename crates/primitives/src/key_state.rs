use crate::domain::DomainId;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// An EpochId uniquely identifies a ThresholdParameters (but not vice-versa).
/// Every time we change the ThresholdParameters (participants and threshold),
/// we increment EpochId.
/// Locally on each node, each keyshare is uniquely identified by the tuple
/// (EpochId, DomainId, AttemptId).
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
    derive_more::Display,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct EpochId(pub u64);

impl EpochId {
    pub const fn new(epoch_id: u64) -> Self {
        EpochId(epoch_id)
    }

    pub const fn next(&self) -> Self {
        EpochId(self.0 + 1)
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

/// Attempt identifier within a key event. Incremented for each attempt within the
/// same epoch and domain.
#[derive(
    Clone,
    Copy,
    Debug,
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
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Display,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AttemptId(pub u64);

impl AttemptId {
    pub fn new() -> Self {
        AttemptId(0)
    }

    pub fn next(&self) -> Self {
        AttemptId(self.0 + 1)
    }

    pub fn get(&self) -> u64 {
        self.0
    }

    pub fn legacy_attempt_id() -> Self {
        AttemptId(0)
    }
}

/// A unique identifier for a key event (generation or resharing):
/// `epoch_id`: identifies the ThresholdParameters that this key is intended to function in.
/// `domain_id`: the domain this key is intended for.
/// `attempt_id`: identifies a particular attempt for this key event, in case multiple attempts
///               yielded partially valid results. This is incremented for each attempt within the
///               same epoch and domain.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct KeyEventId {
    pub epoch_id: EpochId,
    pub domain_id: DomainId,
    pub attempt_id: AttemptId,
}

impl KeyEventId {
    pub fn new(epoch_id: EpochId, domain_id: DomainId, attempt_id: AttemptId) -> Self {
        KeyEventId {
            epoch_id,
            domain_id,
            attempt_id,
        }
    }

    pub fn next_attempt(&self) -> Self {
        KeyEventId {
            epoch_id: self.epoch_id,
            domain_id: self.domain_id,
            attempt_id: self.attempt_id.next(),
        }
    }
}
