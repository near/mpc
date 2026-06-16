use elliptic_curve::{
    bigint::U256,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
    scalar::IsHigh,
};

use k256::{AffinePoint, ProjectivePoint};

use super::Scalar;

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&point.x())
}

/// Represents a signature that supports different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars.
/// The first is derived from using the x-coordinate of an elliptic curve point (`big_r`),
/// and the second is computed using the typical ecdsa signing equation.
/// Deriving the x-coordination implies losing information about `big_r`, some variants
/// may thus include an extra information to recover this point.
///
/// This signature supports all variants by containing `big_r` entirely
#[derive(Debug, Clone)]
pub struct Signature {
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}

impl Signature {
    // This verification tests the signature including whether s has been normalized
    pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
        let r: Scalar = x_coordinate(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        // Check if s has been normalized
        if self.s.is_high().into() {
            return false;
        }
        // tested earlier is not zero, so inversion will not raise an error and unwrap cannot panic
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
            + (ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate(&reproduced.into()) == r
    }
}

/// None for participants and Some for coordinator
pub type SignatureOption = Option<Signature>;

#[cfg(test)]
mod test {
    use super::Signature;
    use crate::ecdsa::Scalar;
    use crate::test_utils::MockCryptoRng;

    use elliptic_curve::ops::{Invert, LinearCombination, Reduce};
    use k256::{
        ProjectivePoint, Secp256k1,
        ecdsa::{SigningKey, signature::Verifier},
    };
    use rand::SeedableRng;
    use sha2::{Digest, Sha256, digest::FixedOutput};

    #[test]
    fn test_verify() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let msg = b"Hello from Near";
        let mut hasher = Sha256::new();
        hasher.update(msg);

        let sk = SigningKey::random(&mut rng);
        let pk = ecdsa::VerifyingKey::from(&sk);
        let (sig, _) = sk.sign_digest_recoverable(hasher.clone()).unwrap();
        assert!(pk.verify(msg, &sig).is_ok());

        let z_bytes = hasher.clone().finalize_fixed();
        let z =
            <Scalar as Reduce<<Secp256k1 as elliptic_curve::Curve>::Uint>>::reduce_bytes(&z_bytes);
        let (r, s) = sig.split_scalars();
        let s_inv = *s.invert_vartime();
        let u1 = z * s_inv;
        let u2 = *r * s_inv;
        let pk = ProjectivePoint::from(pk.as_affine());
        let big_r =
            ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &pk, &u2).to_affine();

        let full_sig = Signature {
            big_r,
            s: *s.as_ref(),
        };

        let is_verified = full_sig.verify(&pk.to_affine(), &z);
        // Should always be ok as signature contains Uint i.e. normalized elements
        assert!(is_verified);
    }
}
