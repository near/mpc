use std::fmt::Display;

use hkdf::Hkdf;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::CurveArithmetic;
use k256::{Scalar, Secp256k1, U256};
use sha2::{Digest, Sha256};

pub trait ScalarExt {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl ScalarExt for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        Scalar::from_uint_unchecked(U256::from_le_slice(bytes))
    }
}

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

// Constant prefix that ensures epsilon derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";
// Constant prefix that ensures delta derivation values are used specifically fors
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const DELTA_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 delta derivation:";

// #[cfg(not(feature = "wasm"))]
// pub fn derive_epsilon(signer_id: &near_primitives::types::AccountId, path: &str) -> Scalar {
//     // TODO: Use a key derivation library instead of doing this manually.
//     // https://crates.io/crates/hkdf might be a good option?
//     //
//     // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
//     // of the accound id in the trie key. We reuse the same constant to
//     // indicate the end of the account id in derivation path.
//     let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", signer_id, path);
//     let mut hasher = Sha256::new();
//     hasher.update(derivation_path);
//     Scalar::from_bytes(&hasher.finalize())
// }

pub fn derive_epsilon(signer_id: &dyn Display, path: &str) -> Scalar {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", signer_id, path);
    let mut hasher = Sha256::new();
    hasher.update(derivation_path);
    Scalar::from_bytes(&hasher.finalize())
}

// In case there are multiple requests in the same block (hence same entropy), we need to ensure
// that we generate different random scalars as delta tweaks.
// Receipt ID should be unique inside of a block, so it serves us as the request identifier.
// receipt_id: CryptoHash of the request.
pub fn derive_delta(receipt_id: [u8; 32], entropy: [u8; 32]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(None, &entropy);
    let info = format!("{DELTA_DERIVATION_PREFIX}:{}", base58_encode(&receipt_id));
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm).unwrap();
    Scalar::from_bytes(&okm)
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

// This is the Display impl for CryptoHash. It is used to get a generalized type for calling
// into derive_epsilon.
fn base58_encode(data: &[u8]) -> String {
    let mut buffer = [0u8; 45];
    let len = bs58::encode(data).onto(&mut buffer[..]).unwrap();
    let val = std::str::from_utf8(&buffer[..len]).unwrap();
    val.into()
}
