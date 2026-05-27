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
    /// Fails with [`ThresholdError::IntegerOverflow`] if `ReconstructionThreshold == 0`.
    /// The auto-derived `From<usize>` and `Deserialize` impls accept 0, so this
    /// validation is required at use-time.
    pub fn max_malicious(self) -> Result<MaxMalicious, ThresholdError> {
        self.0
            .checked_sub(1)
            .map(MaxMalicious)
            .ok_or(ThresholdError::IntegerOverflow)
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn max_malicious__round_trips_via_reconstruction_threshold() {
        // Given: every non-zero reconstruction threshold in a representative range
        for n in 1usize..=64 {
            let t = ReconstructionThreshold::from(n);

            // When: derive MaxMalicious then map back via the inverse
            let recovered = t.max_malicious().unwrap().reconstruction_threshold().unwrap();

            // Then: the round-trip is the identity
            assert_eq!(recovered, t, "round-trip failed for n={n}");
        }
    }

    #[test]
    fn max_malicious__should_err_when_reconstruction_threshold_is_zero() {
        // Given: the unsafe construction path (auto-derived From<usize>) admits zero
        let t = ReconstructionThreshold::from(0usize);

        // When
        let result = t.max_malicious();

        // Then: the underflow is reported instead of silently wrapping
        assert_eq!(result, Err(ThresholdError::IntegerOverflow));
    }

    #[test]
    fn reconstruction_threshold__should_err_on_overflow_at_usize_max() {
        // Given: MaxMalicious holds usize::MAX (only reachable via the unsafe ctor)
        let m = MaxMalicious::from(usize::MAX);

        // When
        let result = m.reconstruction_threshold();

        // Then
        assert_eq!(result, Err(ThresholdError::IntegerOverflow));
    }
}
