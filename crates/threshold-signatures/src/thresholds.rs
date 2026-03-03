use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ThresholdError {
    #[error("integer overflow")]
    IntegerOverflow,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct MaxMalicious(usize);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
}

/// Lower bound to reconstruct the secret is `MaxMalicious` + 1.
impl TryFrom<MaxMalicious> for ReconstructionLowerBound {
    type Error = ThresholdError;

    fn try_from(m: MaxMalicious) -> Result<Self, Self::Error> {
        m.0.checked_add(1)
            .map(Self)
            .ok_or(ThresholdError::IntegerOverflow)
    }
}
