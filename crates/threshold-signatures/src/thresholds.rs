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

    /// The threshold as a `usize`, for indexing and sizing collections in the
    /// protocol code. Lossless on all supported (>= 32-bit) targets.
    ///
    /// # Panics
    ///
    /// Panics only if the threshold exceeds `usize::MAX` — impossible on
    /// supported targets, where a participant count always fits in `usize`.
    pub fn as_usize(self) -> usize {
        usize::try_from(self.0).expect("reconstruction threshold fits in usize")
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
