use sha2::{Digest, Sha256};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::serde::encode_writer;

const COMMIT_LABEL: &[u8] = b"Near threshold signature commitment";
const COMMIT_LEN: usize = 32;
const RANDOMIZER_LEN: usize = 32;
const HASH_LABEL: &[u8] = b"Near threshold signature generic hash";
const HASH_LEN: usize = 32;

/// Represents the randomizer used to make a commit hiding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Randomizer([u8; RANDOMIZER_LEN]);

impl Randomizer {
    /// Generate a new randomizer value by sampling from an RNG.
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut out = [0u8; RANDOMIZER_LEN];
        rng.fill_bytes(&mut out);
        Self(out)
    }
}

impl AsRef<[u8]> for Randomizer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a commitment to some value.
///
/// This commit is both binding, in that it can't be opened to a different
/// value than the one committed, and hiding, in that it hides the value
/// committed inside (perfectly).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment([u8; COMMIT_LEN]);

impl Commitment {
    fn compute<T: Serialize>(val: &T, r: &Randomizer) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(COMMIT_LABEL);
        hasher.update(r.as_ref());
        hasher.update(b"start data");
        encode_writer(&mut hasher, val);
        Commitment(hasher.finalize().into())
    }

    /// Check that a value and a randomizer match this commitment.
    #[must_use]
    pub fn check<T: Serialize>(&self, val: &T, r: &Randomizer) -> bool {
        let actual = Self::compute(val, r);
        *self == actual
    }
}

/// Commit to an arbitrary serializable value.
///
/// This also returns a fresh randomizer, which is used to make sure that the
/// commitment perfectly hides the value contained inside.
///
/// This value will need to be sent when opening the commitment to allow
/// others to check that the opening is valid.
pub fn commit<T: Serialize, R: CryptoRngCore>(rng: &mut R, val: &T) -> (Commitment, Randomizer) {
    let r = Randomizer::random(rng);
    let c = Commitment::compute(val, &r);
    (c, r)
}

/// The output of a generic hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput([u8; HASH_LEN]);

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash some value to produce a short digest.
pub fn hash<T: Serialize>(val: &T) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update(HASH_LABEL);
    encode_writer(&mut hasher, val);
    HashOutput(hasher.finalize().into())
}
