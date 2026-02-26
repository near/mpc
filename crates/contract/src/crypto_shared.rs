pub mod kdf;
pub mod types;

use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint};
pub use kdf::{derive_foreign_tx_tweak, derive_key_secp256k1, derive_tweak};
pub use types::{
    k256_types::{self},
    CKDResponse,
};

// Our wasm runtime doesn't support good synchronous entropy.
// We could use something VRF + pseudorandom here, but someone would likely shoot themselves in the foot with it.
// Our crypto libraries should definitely panic, because they normally expect randomness to be private
#[cfg(target_arch = "wasm32")]
use getrandom::{register_custom_getrandom, Error};
#[cfg(target_arch = "wasm32")]
pub fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
register_custom_getrandom!(randomness_unsupported);

pub fn near_public_key_to_affine_point(pk: near_sdk::PublicKey) -> k256_types::PublicKey {
    // TODO: We should encode the curve type as a generic parameter to the key,
    // to enforce this check at compile time.
    assert_eq!(
        pk.curve_type(),
        near_sdk::CurveType::SECP256K1,
        "Expected a key on the SECP256K1 curve"
    );

    let mut bytes = pk.into_bytes();
    bytes[0] = 0x04;
    let point = EncodedPoint::from_bytes(bytes).unwrap();
    k256_types::PublicKey::from_encoded_point(&point).unwrap()
}
