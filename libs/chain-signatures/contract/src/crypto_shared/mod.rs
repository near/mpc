pub mod kdf;
pub mod types;

use k256::elliptic_curve::CurveArithmetic;
use k256::EncodedPoint;
use k256::{elliptic_curve::sec1::FromEncodedPoint, Secp256k1};
pub use kdf::{derive_key_secp256k1, derive_tweak, x_coordinate};
pub use types::{
    k256_types, k256_types::SerializableAffinePoint, k256_types::SerializableScalar,
    Ed25519PublicKey, ScalarExt, SignatureResponse,
};

// Our wasm runtime doesn't support good syncronous entropy.
// We could use something VRF + pseudorandom here, but someone would likely shoot themselves in the foot with it.
// Our crypto libraries should definately panic, because they normally expect randomness to be private
#[cfg(target_arch = "wasm32")]
use getrandom::{register_custom_getrandom, Error};
#[cfg(target_arch = "wasm32")]
pub fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
register_custom_getrandom!(randomness_unsupported);

pub fn near_public_key_to_affine_point(
    pk: near_sdk::PublicKey,
) -> <Secp256k1 as CurveArithmetic>::AffinePoint {
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
    <Secp256k1 as CurveArithmetic>::AffinePoint::from_encoded_point(&point).unwrap()
}

pub fn near_public_key_to_edwards_point(pk: near_sdk::PublicKey) -> curve25519_dalek::EdwardsPoint {
    // TODO: We should encode the curve type as a generic parameter to the key,
    // to enforce this check at compile time.
    assert_eq!(
        pk.curve_type(),
        near_sdk::CurveType::ED25519,
        "Expected a key on the ED25519 curve"
    );

    let bytes = pk.into_bytes();
    // discard  the curve type prefix
    let key_bytes: [u8; 32] = bytes[1..].try_into().expect("Invalid ED25519 key length");

    // Convert bytes to an EdwardsPoint using the compressed representation
    curve25519_dalek::edwards::CompressedEdwardsY(key_bytes)
        .decompress()
        .expect("The key is a valid y coordinate of a curve point")
}
