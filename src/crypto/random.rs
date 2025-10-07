use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::constants::RANDOMIZER_LEN;

/// Represents the randomizer used to make a commit hiding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Randomness([u8; RANDOMIZER_LEN]);
impl Randomness {
    /// Generate a new randomizer value by sampling from an RNG.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut out = [0u8; RANDOMIZER_LEN];
        rng.fill_bytes(&mut out);
        Self(out)
    }
}

impl AsRef<[u8]> for Randomness {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
