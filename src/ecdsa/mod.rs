//! This module serves as a wrapper for ECDSA scheme.
pub mod dkg_ecdsa;
pub mod ot_based_ecdsa;
pub mod robust_ecdsa;
#[cfg(test)]
mod test;

use elliptic_curve::{
    bigint::U256,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
};

use frost_secp256k1::{Field, Secp256K1ScalarField, Secp256K1Sha256};
use k256::{AffinePoint, ProjectivePoint};

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

pub type KeygenOutput = crate::KeygenOutput<Secp256K1Sha256>;

pub type Scalar = <Secp256K1ScalarField as Field>::Scalar;
pub type CoefficientCommitment = frost_core::keys::CoefficientCommitment<Secp256K1Sha256>;
pub type Polynomial = crate::crypto::polynomials::Polynomial<Secp256K1Sha256>;
pub type PolynomialCommitment = crate::crypto::polynomials::PolynomialCommitment<Secp256K1Sha256>;

impl ScalarSerializationFormat for Secp256K1Sha256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::BigEndian
    }
}

impl Ciphersuite for Secp256K1Sha256 {}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&point.x())
}

/// Represents a signature that supports different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars.
/// The first is derived from using the x-coordinate of an elliptic curve point (big_r),
/// and the second is computed using the typical ecdsa signing equation.
/// Deriving the x-coordination implies losing information about big_r, some variants
/// may thus include an extra information to recover this point.
///
/// This signature supports all variants by containing big_r entirely
#[derive(Clone)]
pub struct FullSignature {
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}

impl FullSignature {
    #[must_use]
    // This verification tests the signature including whether s has been normalized
    pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
        let r: Scalar = x_coordinate(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        // tested earlier is not zero, so inversion will not raise an error and unwrap cannot panic
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
            + (ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate(&reproduced.into()) == r
    }
}

#[cfg(test)]
mod test_verify {
    use super::FullSignature;
    use elliptic_curve::ops::{Invert, LinearCombination, Reduce};
    use k256::{
        ecdsa::{signature::Verifier, SigningKey, VerifyingKey},
        ProjectivePoint, Scalar, Secp256k1,
    };
    use rand_core::OsRng;
    use sha2::{digest::FixedOutput, Digest, Sha256};

    #[test]
    fn test_verify() {
        let msg = b"Hello from Near";
        let mut hasher = Sha256::new();
        hasher.update(msg);

        for _ in 0..100 {
            let sk = SigningKey::random(&mut OsRng);
            let pk = VerifyingKey::from(&sk);
            let (sig, _) = sk.sign_digest_recoverable(hasher.clone()).unwrap();
            assert!(pk.verify(msg, &sig).is_ok());

            let z_bytes = hasher.clone().finalize_fixed();
            let z = <Scalar as Reduce<<Secp256k1 as elliptic_curve::Curve>::Uint>>::reduce_bytes(
                &z_bytes,
            );
            let (r, s) = sig.split_scalars();
            let s_inv = *s.invert_vartime();
            let u1 = z * s_inv;
            let u2 = *r * s_inv;
            let pk = ProjectivePoint::from(pk.as_affine());
            let big_r =
                ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &pk, &u2).to_affine();

            let full_sig = FullSignature {
                big_r,
                s: *s.as_ref(),
            };

            let is_verified = full_sig.verify(&pk.to_affine(), &z);
            // Should always be ok as signature contains Uint i.e. normalized elements
            assert!(is_verified)
        }
    }
}
