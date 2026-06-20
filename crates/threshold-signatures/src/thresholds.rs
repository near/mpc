use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct MaxMalicious(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReconstructionThreshold(u64);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionThreshold {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn inner(self) -> u64 {
        self.0
    }

    /// The threshold as a `usize`, for indexing and sizing collections.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::IntegerOverflow`] if the threshold exceeds `usize::MAX`
    /// — unreachable on supported (>= 32-bit) targets.
    pub fn try_as_usize(self) -> Result<usize, ThresholdError> {
        usize::try_from(self.0).map_err(|_| ThresholdError::IntegerOverflow)
    }
}

/// Construct from a `usize` participant count. `usize` → `u64` is lossless on
/// all supported targets. Provided (instead of `derive_more::From<u64>`) so that
/// untyped integer literals like `ReconstructionThreshold::from(3)` infer cleanly
/// and the crypto crate keeps its `usize`-based construction ergonomics; the node
/// constructs the `u64`-backed value via [`ReconstructionThreshold::new`].
impl From<usize> for ReconstructionThreshold {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

/// Lower bound to reconstruct the secret is `MaxMalicious` + 1.
impl TryFrom<MaxMalicious> for ReconstructionThreshold {
    type Error = ThresholdError;

    fn try_from(m: MaxMalicious) -> Result<Self, Self::Error> {
        u64::try_from(m.0)
            .ok()
            .and_then(|v| v.checked_add(1))
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
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn reconstruction_threshold__should_round_trip_through_new_and_inner() {
        // Given
        let threshold = ReconstructionThreshold::new(3);

        // When
        let inner = threshold.inner();

        // Then
        assert_eq!(inner, 3);
        assert_eq!(ReconstructionThreshold::new(inner), threshold);
    }

    #[test]
    fn reconstruction_threshold__should_round_trip_through_from_usize_and_try_as_usize() {
        // Given
        let threshold = ReconstructionThreshold::from(5usize);

        // When
        let as_usize = threshold.try_as_usize();

        // Then
        assert_eq!(as_usize, Ok(5usize));
        assert_eq!(ReconstructionThreshold::from(as_usize.unwrap()), threshold);
    }

    #[test]
    fn try_as_usize__should_return_ok_for_representable_value() {
        // Given
        let threshold = ReconstructionThreshold::new(7);

        // When
        let result = threshold.try_as_usize();

        // Then
        assert_eq!(result, Ok(7usize));
    }

    #[test]
    fn try_from_max_malicious__should_be_max_malicious_plus_one() {
        // Given
        let max_malicious = MaxMalicious::from(4usize);

        // When
        let threshold = ReconstructionThreshold::try_from(max_malicious);

        // Then
        assert_eq!(threshold, Ok(ReconstructionThreshold::new(5)));
    }

    #[test]
    fn try_from_max_malicious__should_overflow_when_at_usize_max() {
        // Given
        let max_malicious = MaxMalicious::from(usize::MAX);

        // When
        let result = ReconstructionThreshold::try_from(max_malicious);

        // Then
        assert_eq!(result, Err(ThresholdError::IntegerOverflow));
    }
}
