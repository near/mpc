use contract_interface::types::{
    Ed25519PublicKey, Ed25519Signature, Hash256, K256Signature, Payload, PublicKey,
    Secp256k1PublicKey, SignatureResponse,
};
use k256::{
    EncodedPoint, Secp256k1,
    elliptic_curve::{CurveArithmetic, point::AffineCoordinates, sec1::ToEncodedPoint},
};

pub enum VerificationError {
    InvalidSignature,
    FailedToRecoverSignature,
    RecoveredPkDoesNotMatchExpectedKey,
}

pub fn check_ec_signature_helper(
    expected_pk: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: &[u8; 32],
    recovery_id: u8,
) -> Result<(), VerificationError> {
    let public_key = expected_pk.to_encoded_point(false);
    let x_coordinate =
        <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
            <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
        >>::reduce_bytes(&big_r.x());

    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate, s)
        .map_err(|_| VerificationError::InvalidSignature)?;

    let recovered_key_bytes =
        near_sdk::env::ecrecover(msg_hash, &signature.to_bytes(), recovery_id, true)
            .ok_or(VerificationError::FailedToRecoverSignature)?;

    let verifying_key = k256::ecdsa::VerifyingKey::from_encoded_point(
        &EncodedPoint::from_untagged_bytes(&recovered_key_bytes.into()),
    )
    .expect("todo")
    .to_encoded_point(false);

    if verifying_key != public_key {
        return Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey);
    }
    Ok(())
}

pub fn check_ec_signature(
    signature: &K256Signature,
    message: &Hash256,
    public_key: &Secp256k1PublicKey,
) -> Result<(), VerificationError> {
    todo!("somehow verify. We can use check_ec_signature_helper.")
}

pub fn check_ed_signature(
    signature: &Ed25519Signature,
    message: &Hash256,
    public_key: &Ed25519PublicKey,
) -> Result<(), VerificationError> {
    let is_valid_signature = near_sdk::env::ed25519_verify(signature, message.as_ref(), public_key);
    if is_valid_signature {
        Ok(())
    } else {
        Err(VerificationError::InvalidSignature)
    }
}
