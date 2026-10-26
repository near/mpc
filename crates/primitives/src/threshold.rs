use crate::participant_count::ParticipantCount;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Network-wide governance threshold (`k`): the minimum number of participants
/// that must agree to approve a governance action (participant set changes,
/// resharing, parameter updates). Distinct from a domain's
/// [`ReconstructionThreshold`], the per-domain `t` needed to reconstruct a key.
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
pub struct GovernanceThreshold(pub u64);

impl GovernanceThreshold {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(self) -> u64 {
        self.0
    }

    /// True when `count` participants are at least this many.
    pub fn is_met_by(self, count: ParticipantCount) -> bool {
        count.value() >= self.0
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

    /// True when `count` participants are at least this many.
    pub fn is_met_by(self, count: ParticipantCount) -> bool {
        count.value() >= self.0
    }
}

impl From<GovernanceThreshold> for ReconstructionThreshold {
    fn from(value: GovernanceThreshold) -> Self {
        Self(value.value())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{GovernanceThreshold, ParticipantCount, ReconstructionThreshold};

    #[test]
    fn is_met_by__should_hold_at_and_above_the_threshold_only() {
        // Given
        let governance = GovernanceThreshold::new(3);
        let reconstruction = ReconstructionThreshold::new(3);
        let counts = [2, 3, 4].map(ParticipantCount::new);

        // When
        let met =
            counts.map(|count| (governance.is_met_by(count), reconstruction.is_met_by(count)));

        // Then
        assert_eq!(met, [(false, false), (true, true), (true, true)]);
    }
}
