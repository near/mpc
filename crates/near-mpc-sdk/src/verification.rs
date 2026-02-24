use k256::{
    EncodedPoint, Secp256k1,
    ecdsa::{RecoveryId, Signature},
    elliptic_curve::{CurveArithmetic, PrimeField, point::AffineCoordinates, sec1::ToEncodedPoint},
};

use crate::sign;

enum VerificationError {
    InvalidSignature,
    FailedToRecoverSignature,
    RecoveredPkDoesNotMatchExpectedKey,
}

fn check_ec_signature(
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
    .expect("todo");

    if verifying_key != public_key {
        return Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey);
    }
    Ok(())
}
