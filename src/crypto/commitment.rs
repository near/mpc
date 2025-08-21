use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::errors::ProtocolError;

use super::random::Randomness;

const COMMIT_LABEL: &[u8] = b"Near threshold signature commitment";
const COMMIT_LEN: usize = 32;
const START_LABEL: &[u8] = b"start data";

/// Represents a commitment to some value.
///
/// This commit is both binding, in that it can't be opened to a different
/// value than the one committed, and hiding, in that it hides the value
/// committed inside (perfectly).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment([u8; COMMIT_LEN]);

impl Commitment {
    /// Computes the commitment using a randomizer as follows
    /// SHA256(COMMIT_LABEL || randomness || START_LABEL || msgpack(value))
    fn compute<T: Serialize>(val: &T, r: &Randomness) -> Result<Self, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(COMMIT_LABEL);
        hasher.update(r.as_ref());
        hasher.update(START_LABEL);
        rmp_serde::encode::write(&mut hasher, val).map_err(|_| ProtocolError::ErrorEncoding)?;
        Ok(Commitment(hasher.finalize().into()))
    }

    /// Check that a value and a randomizer match this commitment.
    pub fn check<T: Serialize>(&self, val: &T, r: &Randomness) -> Result<bool, ProtocolError> {
        let actual = Self::compute(val, r)?;
        Ok(*self == actual)
    }
}

/// Commit to an arbitrary serializable value.
///
/// This also returns a fresh randomizer, which is used to make sure that the
/// commitment perfectly hides the value contained inside.
///
/// This value will need to be sent when opening the commitment to allow
/// others to check that the opening is valid.
pub fn commit<T: Serialize, R: CryptoRngCore>(
    rng: &mut R,
    val: &T,
) -> Result<(Commitment, Randomness), ProtocolError> {
    let r = Randomness::random(rng);
    let c = Commitment::compute(val, &r)?;
    Ok((c, r))
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use super::commit;

    #[test]
    fn test_commitment_is_valid() {
        let val = "Committed value";
        let (c, r) = commit(&mut OsRng, &val).unwrap();
        assert!(c.check(&val, &r).unwrap());
    }

    #[test]
    fn test_commitment_is_invalid() {
        let val1 = "Committed value";
        let (c1, r1) = commit(&mut OsRng, &val1).unwrap();

        let val2 = "Another committed value";
        let (c2, r2) = commit(&mut OsRng, &val2).unwrap();

        assert!(!c1.check(&val1, &r2).unwrap());
        assert!(!c1.check(&val2, &r1).unwrap());
        assert!(!c2.check(&val1, &r2).unwrap());
        assert!(!c2.check(&val2, &r1).unwrap());
    }
}
