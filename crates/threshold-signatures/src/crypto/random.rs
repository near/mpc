use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use super::constants::RANDOMIZER_LEN;

/// Represents the randomizer used to make a commit hiding.
#[derive(Clone, Copy, Serialize, Deserialize, derive_more::AsRef)]
pub struct Randomness([u8; RANDOMIZER_LEN]);

impl std::fmt::Debug for Randomness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Randomness(<redacted>)")
    }
}

impl ConstantTimeEq for Randomness {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Randomness {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for Randomness {}
impl Randomness {
    /// Generate a new randomizer value by sampling from an RNG.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut out = [0u8; RANDOMIZER_LEN];
        rng.fill_bytes(&mut out);
        Self(out)
    }
}
