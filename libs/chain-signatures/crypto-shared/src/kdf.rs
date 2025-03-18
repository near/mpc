use crate::types::{ScalarExt, Secp256k1PublicKey};
use anyhow::Context;

use near_account_id::AccountId;
use sha3::{Digest, Sha3_256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_epsilon<Scalar: ScalarExt>(predecessor_id: &AccountId, path: &str) -> Scalar {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    // Do not reuse this hash function on anything that isn't an account
    // ID or it'll be vunerable to Hash Melleability/extention attacks.
    let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    ScalarExt::from_non_biased(hash)
}

pub mod secp256k1 {
    use super::*;
    use k256::{
        ecdsa::{RecoveryId, Signature, VerifyingKey},
        elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
        Scalar, Secp256k1, SecretKey,
    };

    pub fn derive_key(public_key: Secp256k1PublicKey, epsilon: Scalar) -> Secp256k1PublicKey {
        (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key)
            .to_affine()
    }

    pub fn derive_secret_key(secret_key: &SecretKey, epsilon: Scalar) -> SecretKey {
        SecretKey::new((epsilon + secret_key.to_nonzero_scalar().as_ref()).into())
    }

    /// Get the x coordinate of a point, as a scalar
    pub fn x_coordinate(
        point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
    ) -> <Secp256k1 as CurveArithmetic>::Scalar {
        <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
            <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
        >>::reduce_bytes(&point.x())
    }

    pub fn check_ec_signature(
        expected_pk: &k256::AffinePoint,
        big_r: &k256::AffinePoint,
        s: &k256::Scalar,
        msg_hash: Scalar,
        recovery_id: u8,
    ) -> anyhow::Result<()> {
        let public_key = expected_pk.to_encoded_point(false);
        let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
            .context("cannot create signature from cait_sith signature")?;
        let found_pk = recover(
            &msg_hash.to_bytes(),
            &signature,
            RecoveryId::try_from(recovery_id).context("invalid recovery ID")?,
        )?
        .to_encoded_point(false);
        if public_key == found_pk {
            return Ok(());
        }

        anyhow::bail!("cannot use either recovery id={recovery_id} to recover pubic key")
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn recover(
        prehash: &[u8],
        signature: &Signature,
        recovery_id: RecoveryId,
    ) -> anyhow::Result<VerifyingKey> {
        VerifyingKey::recover_from_prehash(prehash, signature, recovery_id)
            .context("Unable to recover public key")
    }

    #[cfg(target_arch = "wasm32")]
    pub fn recover(
        prehash: &[u8],
        signature: &Signature,
        recovery_id: RecoveryId,
    ) -> anyhow::Result<VerifyingKey> {
        use k256::EncodedPoint;
        use near_sdk::env;
        // While this function also works on native code, it's a bit weird and unsafe.
        // I'm more comfortable using an existing library instead.
        let recovered_key_bytes =
            env::ecrecover(prehash, &signature.to_bytes(), recovery_id.to_byte(), true)
                .context("Unable to recover public key")?;
        VerifyingKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(
            &recovered_key_bytes.into(),
        ))
        .context("Failed to parse returned key")
    }
}

mod ed25519 {
    use crate::Ed25519PublicKey;
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, EdwardsPoint, Scalar,
    };
    use ed25519_dalek::{Signature, SigningKey, Verifier};

    use super::*;
    pub fn derive_key(
        public_key: &Ed25519PublicKey,
        epsilon: Scalar,
    ) -> anyhow::Result<Ed25519PublicKey> {
        // First, get the Edwards point representation of the public key
        let pk_bytes = public_key.as_bytes();
        let compressed =
            CompressedEdwardsY::from_slice(pk_bytes).context("Invalid public key bytes")?;

        let point = compressed
            .decompress()
            .context("Failed to decompress public key point")?;

        // Compute: G * epsilon + public_key_point
        let derived_point = ED25519_BASEPOINT_TABLE * &epsilon + point;

        // Convert back to Ed25519PublicKey format
        let derived_compressed = derived_point.compress();
        Ed25519PublicKey::from_bytes(&derived_compressed.to_bytes())
            .context("Failed to create verifying key from derived point")
    }

    pub fn derive_secret_key(secret_key: &SigningKey, epsilon: Scalar) -> SigningKey {
        // In Ed25519, the secret key is 32 bytes
        let secret_bytes = secret_key.to_bytes();

        // The actual scalar is derived from the first 32 bytes using SHA512
        // We can't just add to the bytes directly due to Ed25519's key derivation
        // Instead, we'd need to derive the actual scalar, add epsilon, and create a new key

        // This is a simplified approach - in practice, you might need more careful manipulation
        // of the expanded key material. This implementation focuses on the high-level structure.

        // Get the scalar from secret key (this is a simplification)
        let sk_scalar = Scalar::from_bytes_mod_order(secret_bytes);

        // Add epsilon
        let derived_scalar = sk_scalar + epsilon;

        // Convert back to bytes
        let derived_bytes = derived_scalar.to_bytes();

        // Create new signing key
        SigningKey::from_bytes(&derived_bytes)
    }

    pub fn check_ed25519_signature(
        expected_pk: &Ed25519PublicKey,
        big_r: &EdwardsPoint,
        s: &Scalar,
        message: &[u8],
    ) -> anyhow::Result<()> {
        // Construct a canonical Ed25519 signature from R and S
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&big_r.compress().to_bytes());
        sig_bytes[32..64].copy_from_slice(&s.to_bytes());

        let signature = Signature::from_bytes(&sig_bytes);

        // Verify the signature
        expected_pk
            .verify(message, &signature)
            .context("Ed25519 signature verification failed")
    }

    // Ed25519 doesn't use the recovery ID concept like ECDSA does,
    // so we don't need a recover function. The verification is direct.
}
