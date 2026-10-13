use elliptic_curve::{
    bigint::U256,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
    scalar::IsHigh,
};

use k256::{AffinePoint, ProjectivePoint, ecdsa::RecoveryId};

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
/// Deriving the x-coordinate implies losing information about `big_r`, some variants
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
    /// Verifies the signature, including whether `s` has been normalized.
    ///
    /// Runs in variable time (early returns, [`Invert::invert_vartime`]).
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

    /// Finds the [`RecoveryId`] under which this signature and `msg_hash` recover `public_key`,
    /// as needed by verifiers that recover the signer's key instead of taking it as input.
    ///
    /// Only the x-coordinate of [`Self::big_r`] is used: signing negates `s` to normalize it
    /// but leaves `big_r` as is, so the y-parity of `big_r` may not match the signature.
    pub fn recovery_id(
        &self,
        public_key: &AffinePoint,
        msg_hash: &[u8; 32],
    ) -> Result<RecoveryId, k256::ecdsa::Error> {
        let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(&self.big_r), self.s)?;
        let public_key = k256::ecdsa::VerifyingKey::from_affine(*public_key)?;
        RecoveryId::trial_recovery_from_prehash(&public_key, msg_hash, &signature)
    }
}

/// None for participants and Some for coordinator
pub type SignatureOption = Option<Signature>;

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use super::Signature;
    use crate::ecdsa::Scalar;
    use crate::test_utils::MockCryptoRng;

    use elliptic_curve::ops::{Invert, LinearCombination, Reduce};
    use elliptic_curve::{PrimeField, point::DecompressPoint};
    use k256::{
        AffinePoint, ProjectivePoint, Secp256k1,
        ecdsa::{SigningKey, signature::Verifier},
    };
    use rand::{RngCore, SeedableRng};
    use sha2::{Digest, Sha256, digest::FixedOutput};

    #[test]
    fn verify__should_accept_valid_signature() {
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

    #[test]
    fn recovery_id__should_match_recovery_id_from_k256_signing() {
        for seed in 0..256 {
            // Given
            // generate a pair of ecdsa keys
            let mut rng = MockCryptoRng::seed_from_u64(seed);
            let signing_key = SigningKey::random(&mut rng);

            // compute a signature with recovery id
            let mut prehash = [0u8; 32];
            rng.fill_bytes(&mut prehash);
            let (signature, expected_recovery_id) =
                signing_key.sign_prehash_recoverable(&prehash).unwrap();
            let (r, s) = signature.split_scalars();

            // Create a full signature
            // any big_r creation works here as we only need its x coordinate (big_r.x())
            let hypothetical_big_r = AffinePoint::decompress(&r.to_repr(), 0.into()).unwrap();
            let full_sig = Signature {
                big_r: hypothetical_big_r,
                s: *s.as_ref(),
            };

            // When
            // compute recovery_id using our function
            let recovery_id = full_sig
                .recovery_id(signing_key.verifying_key().as_affine(), &prehash)
                .unwrap();

            // Then
            assert_eq!(recovery_id, expected_recovery_id);
        }
    }

    #[test]
    fn recovery_id__should_fail_for_public_key_of_another_signer() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let signing_key = SigningKey::random(&mut rng);
        let other_public_key = *SigningKey::random(&mut rng).verifying_key().as_affine();
        let prehash = [7u8; 32];
        let (signature, _) = signing_key.sign_prehash_recoverable(&prehash).unwrap();
        let (r, s) = signature.split_scalars();
        let full_sig = Signature {
            big_r: AffinePoint::decompress(&r.to_repr(), 0.into()).unwrap(),
            s: *s.as_ref(),
        };

        // When
        let result = full_sig.recovery_id(&other_public_key, &prehash);

        // Then
        assert!(result.is_err());
    }
}
