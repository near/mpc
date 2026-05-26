use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Number of share-holders required to reconstruct the secret (`t` in a t-of-n
/// scheme). The single public threshold type exposed by this crate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionThreshold(usize);

/// Maximum number of malicious parties tolerated by a protocol. The module
/// `thresholds` is private, so the only callers are inside this crate —
/// external code stays in [`ReconstructionThreshold`] terms.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct MaxMalicious(usize);

impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }

    /// Number of share-holders needed to reconstruct the secret under this
    /// max-malicious bound. Inverse of [`ReconstructionThreshold::max_malicious`].
    /// Fails only if `MaxMalicious == usize::MAX`.
    #[allow(dead_code)] // used only by test code under cfg(test)
    pub fn reconstruction_threshold(self) -> Result<ReconstructionThreshold, ThresholdError> {
        ReconstructionThreshold::try_from(self)
    }
}

impl ReconstructionThreshold {
    pub fn value(self) -> usize {
        self.0
    }

    /// Maximum number of malicious parties this protocol tolerates, derived
    /// by the standard relation `MaxMalicious = ReconstructionThreshold - 1`.
    ///
    /// Returns a crate-private type — robust ECDSA needs this internally;
    /// external callers stay in `ReconstructionThreshold` terms.
    ///
    /// Panics if `ReconstructionThreshold == 0`; constructors only produce values ≥ 1.
    pub fn max_malicious(self) -> MaxMalicious {
        MaxMalicious(self.0 - 1)
    }
}

/// Standard relation: `ReconstructionThreshold = MaxMalicious + 1`.
impl TryFrom<MaxMalicious> for ReconstructionThreshold {
    type Error = ThresholdError;

    fn try_from(m: MaxMalicious) -> Result<Self, Self::Error> {
        m.0.checked_add(1)
            .map(Self)
            .ok_or(ThresholdError::IntegerOverflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ThresholdError {
    #[error("integer overflow")]
    IntegerOverflow,
}
