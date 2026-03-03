use derive_more::{From, Into};
use serde::{Deserialize, Serialize};

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

/// Lower bound to reconstruct the secret is MaxMalicious + 1.
impl From<MaxMalicious> for ReconstructionLowerBound {
    fn from(m: MaxMalicious) -> Self {
        Self(m.0.checked_add(1).expect("MaxMalicious too large"))
    }
}
