use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::sha2::{Digest, Sha256};
use k256::{Scalar, U256};

pub fn sha256hash(data: &[u8]) -> k256::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Scalar::from_uint_unchecked(U256::from_be_slice(&bytes))
}
