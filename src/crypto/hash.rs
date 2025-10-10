use crate::errors::ProtocolError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use super::constants::{HASH_LEN, NEAR_HASH_LABEL};

/// The output of a generic hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput([u8; HASH_LEN]);

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for HashOutput {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Hash some value to produce a short digest as follows
/// `SHA256(HASH_LABEL` || msgpack(value))
pub fn hash<T: Serialize>(val: &T) -> Result<HashOutput, ProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(NEAR_HASH_LABEL);
    rmp_serde::encode::write(&mut hasher, val).map_err(|_| ProtocolError::ErrorEncoding)?;
    Ok(HashOutput(hasher.finalize().into()))
}

/// Hashes using a domain separator as follows:
/// `SHA256(HASH_LABEL` || msgpack([`domain_separator`, data])
/// This function DOES NOT internally increment the domain separator
pub fn domain_separate_hash<T: Serialize>(
    domain_separator: u32,
    data: &T,
) -> Result<HashOutput, ProtocolError> {
    let preimage = (domain_separator, data);
    hash(&preimage)
}

#[cfg(test)]
pub mod test {
    use elliptic_curve::{ops::Reduce, Curve, CurveArithmetic};
    use subtle::ConstantTimeEq;

    use super::{domain_separate_hash, hash, HashOutput};
    use digest::{Digest, FixedOutput};
    use ecdsa::hazmat::DigestPrimitive;
    use k256::{FieldBytes, Scalar, Secp256k1};

    #[test]
    fn test_same_inputs_hash() {
        let val = ("abc", 123);
        let hash1 = hash(&val).unwrap();
        let hash2 = hash(&val).unwrap();
        assert_eq!(hash1.0, hash2.0);
    }

    #[test]
    fn test_same_inputs_domain_separate_hash() {
        let val = ("abc", 123);
        let hash1 = domain_separate_hash(42, &val).unwrap();
        let hash2 = domain_separate_hash(42, &val).unwrap();
        assert_eq!(hash1.0, hash2.0);
    }

    #[test]
    fn test_different_inputs_hash() {
        let val1 = ("abc", 123);
        let val2 = ("abc", 124);
        let hash1 = hash(&val1).unwrap();
        let hash2 = hash(&val2).unwrap();
        assert_ne!(hash1.0, hash2.0);
    }

    #[test]
    fn test_different_inputs_domain_separate_hash() {
        let val1 = ("abc", 123);
        let val2 = ("abc", 124);
        let hash1 = domain_separate_hash(41, &val1).unwrap();
        let hash2 = domain_separate_hash(42, &val1).unwrap();
        assert_ne!(hash1.0, hash2.0);

        let hash2 = domain_separate_hash(41, &val2).unwrap();
        assert_ne!(hash1.0, hash2.0);
    }

    #[test]
    fn test_ct_eq_equal() {
        let a = HashOutput([1u8; 32]);
        let b = HashOutput([1u8; 32]);
        let result = a.ct_eq(&b);
        assert!(result.unwrap_u8() == 1);
    }

    #[test]
    fn test_ct_eq_not_equal() {
        let a = HashOutput([1u8; 32]);
        let b = HashOutput([2u8; 32]);
        let result = a.ct_eq(&b);
        assert!(result.unwrap_u8() == 0);
    }

    /// Hashes a message string into an arbitrary scalar
    pub fn scalar_hash_secp256k1(msg: &[u8]) -> <Secp256k1 as CurveArithmetic>::Scalar {
        // follows  https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
        let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
        let m_bytes: FieldBytes = digest.finalize_fixed();
        <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
    }
}
