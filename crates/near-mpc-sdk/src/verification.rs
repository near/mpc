use contract_interface::types::{
    Ed25519PublicKey, Ed25519Signature, Hash256, K256Signature, Secp256k1PublicKey,
};
use k256::{
    Secp256k1,
    elliptic_curve::{CurveArithmetic, ops::Reduce},
};

type K256Scalar = <Secp256k1 as CurveArithmetic>::Scalar;
type K256Uint = <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint;

fn reduce_scalar(bytes: k256::FieldBytes) -> K256Scalar {
    <K256Scalar as Reduce<K256Uint>>::reduce_bytes(&bytes)
}

pub enum VerificationError {
    InvalidSignature,
    FailedToRecoverSignature,
    RecoveredPkDoesNotMatchExpectedKey,
}

pub fn check_ec_signature(
    signature: &K256Signature,
    message: &Hash256,
    public_key: &Secp256k1PublicKey,
) -> Result<(), VerificationError> {
    // x-coordinate is bytes [1..33] of the 33-byte compressed point
    let r_bytes: [u8; 32] = signature.big_r.affine_point[1..].try_into().unwrap();
    let r = reduce_scalar(r_bytes.into());
    let s = reduce_scalar(signature.s.scalar.into());
    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(r, s)
        .map_err(|_| VerificationError::InvalidSignature)?;
    let recovered = near_sdk::env::ecrecover(
        &message.0,
        &ecdsa_sig.to_bytes(),
        signature.recovery_id,
        true,
    )
    .ok_or(VerificationError::FailedToRecoverSignature)?;

    if recovered != public_key.0 {
        return Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey);
    }
    Ok(())
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
