use crate::crypto_shared::types::k256_types;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
#[cfg(target_arch = "wasm32")]
use k256::EncodedPoint;
use k256::{
    Secp256k1,
    elliptic_curve::{CurveArithmetic, PrimeField, point::AffineCoordinates},
};
use near_mpc_contract_interface::types::Tweak;
#[cfg(target_arch = "wasm32")]
use near_sdk::env;

use near_mpc_contract_interface::types as dtos;

#[derive(Debug, Clone)]
pub struct TweakNotOnCurve;

pub fn derive_key_secp256k1(
    public_key: &k256_types::PublicKey,
    tweak: &Tweak,
) -> Result<dtos::Secp256k1PublicKey, TweakNotOnCurve> {
    let tweak = k256::Scalar::from_repr(tweak.as_bytes().into())
        .into_option()
        .ok_or(TweakNotOnCurve)?;

    let derived = (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * tweak + public_key)
        .to_affine();
    let pk = k256::PublicKey::try_from(derived).map_err(|_| TweakNotOnCurve)?;
    Ok(dtos::Secp256k1PublicKey::from(&pk))
}

pub fn derive_public_key_edwards_point_ed25519(
    public_key_edwards_point: &curve25519_dalek::EdwardsPoint,
    tweak: &Tweak,
) -> curve25519_dalek::EdwardsPoint {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    public_key_edwards_point + ED25519_BASEPOINT_POINT * tweak
}

pub fn derive_public_key_cheetah(root_be: &[u8], tweak: &Tweak) -> Option<[u8; 97]> {
    let root = cheetah::PublicKey::from_be_bytes(root_be).ok()?;
    let scalar = cheetah::tweak_from_le_bytes(&tweak.as_bytes());
    root.derive_child(&scalar).ok()?.to_be_bytes().ok()
}

/// Verify a Nockchain Cheetah Schnorr signature against the *derived child* key.
///
/// - `root_be`: 97-byte big-endian root public key (as stored in the contract).
/// - `tweak`: chain-signatures epsilon for the request (read little-endian).
/// - `message`: the Cheetah signing payload — the 5-belt Tip5 digest as forty
///   little-endian bytes (`message_from_digest`).
/// - `sig`: `c ‖ s`, two 32-byte little-endian scalars.
pub fn verify_cheetah_signature(
    root_be: &[u8],
    tweak: &Tweak,
    message: &[u8],
    sig: &[u8; 64],
) -> bool {
    let root = match cheetah::PublicKey::from_be_bytes(root_be) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let scalar = cheetah::tweak_from_le_bytes(&tweak.as_bytes());
    let child = match root.derive_child(&scalar) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let digest = cheetah::digest_from_message(message);
    let signature = cheetah::Signature::from_le_bytes(sig);
    child.verify(&signature, &digest)
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::Scalar;
    use near_mpc_contract_interface::types::kdf::derive_tweak;
    use rand::rngs::OsRng;
    use rand::{Rng, SeedableRng};
    use threshold_signatures::frost::eddsa::KeygenOutput;
    use threshold_signatures::frost_core::VerifyingKey;
    use threshold_signatures::frost_core::keys::SigningShare;
    use threshold_signatures::frost_ed25519::{Ed25519Group, Ed25519Sha512, Group, SigningKey};

    #[test]
    fn verify_cheetah_signature_accepts_child_and_rejects_tampering() {
        let root_sk =
            cheetah::PrivateKey::from_be_bytes(&[7u8; 32]).expect("0x07..07 is a canonical scalar");
        let tweak_bytes = [0x5a_u8; 32];
        let tweak = cheetah::tweak_from_le_bytes(&tweak_bytes);

        // The cluster signs for child = root + tweak·G.
        let child_sk = root_sk.derive_child(&tweak);
        let root_be = root_sk.public_key().unwrap().to_be_bytes().unwrap();

        // 5-belt Tip5 digest, encoded as the 40-byte little-endian payload.
        let digest = [11u64, 22, 33, 44, 55];
        let mut message = [0u8; 40];
        for (chunk, &belt) in message.chunks_mut(8).zip(&digest) {
            chunk.copy_from_slice(&belt.to_le_bytes());
        }
        let sig = child_sk.sign(&digest).unwrap().to_le_bytes();

        assert!(
            verify_cheetah_signature(&root_be, &Tweak::new(tweak_bytes), &message, &sig),
            "child signature verifies under root + tweak"
        );

        // Wrong tweak -> wrong derived key -> reject.
        let mut other_tweak = tweak_bytes;
        other_tweak[0] ^= 1;
        assert!(!verify_cheetah_signature(
            &root_be,
            &Tweak::new(other_tweak),
            &message,
            &sig
        ));

        // Tampered signature -> reject.
        let mut bad_sig = sig;
        bad_sig[0] ^= 1;
        assert!(!verify_cheetah_signature(
            &root_be,
            &Tweak::new(tweak_bytes),
            &message,
            &bad_sig
        ));

        // Zero tweak derives to the root key: signing with the root secret then
        // verifies under a zero tweak (and the derived key equals the root).
        let root_sig = root_sk.sign(&digest).unwrap().to_le_bytes();
        assert!(verify_cheetah_signature(
            &root_be,
            &Tweak::new([0u8; 32]),
            &message,
            &root_sig
        ));
        assert_eq!(
            derive_public_key_cheetah(&root_be, &Tweak::new([0u8; 32])),
            Some(root_be),
            "zero tweak is the identity derivation"
        );
    }

    pub(crate) fn derive_keygen_output(
        keygen_output: &KeygenOutput,
        tweak: [u8; 32],
    ) -> KeygenOutput {
        let tweak = Scalar::from_bytes_mod_order(tweak);
        let private_share = SigningShare::new(keygen_output.private_share.to_scalar() + tweak);
        let public_key = VerifyingKey::new(
            keygen_output.public_key.to_element() + Ed25519Group::generator() * tweak,
        );
        KeygenOutput {
            private_share,
            public_key,
        }
    }

    #[test]
    fn test_derivation() {
        let random_bytes: [u8; 32] = rand::thread_rng().r#gen();

        let scalar = Scalar::from_bytes_mod_order(random_bytes);
        let private_share = SigningShare::<Ed25519Sha512>::new(scalar);

        let public_key_element = Ed25519Group::generator() * scalar;
        let public_key = VerifyingKey::<Ed25519Sha512>::new(public_key_element);

        let keygen_output = KeygenOutput {
            private_share,
            public_key,
        };

        let tweak = derive_tweak(&"hello".parse().unwrap(), "my-path");
        let derived_keygen_output = derive_keygen_output(&keygen_output, tweak.as_bytes());

        let derived_public_key =
            derive_public_key_edwards_point_ed25519(&public_key_element, &tweak);

        assert_eq!(
            derived_public_key,
            derived_keygen_output.public_key.to_element()
        );

        // Sanity check of our private key generator.
        assert_eq!(
            derived_keygen_output.public_key.to_element(),
            derived_keygen_output.private_share.to_scalar() * Ed25519Group::generator(),
            "Sanity check failed."
        );

        let message = [1, 2, 3, 4];
        let signer =
            SigningKey::from_scalar(derived_keygen_output.private_share.to_scalar()).unwrap();

        let signature = signer.sign(OsRng, &message);
        let derived_verifying_key = VerifyingKey::new(derived_public_key);
        derived_verifying_key.verify(&message, &signature).unwrap();
    }

    #[test]
    fn test_derive_key_secp256k1_has_not_changed() {
        // given
        let random_bytes: [u8; 32] = rand::rngs::StdRng::from_seed([42u8; 32]).r#gen();
        let tweak = derive_tweak(&"hello".parse().unwrap(), "my-path");
        let scalar = k256::Scalar::from_repr(random_bytes.into()).unwrap();
        let public_key_element = k256::ProjectivePoint::GENERATOR * scalar;

        // when
        let derived_public_key =
            derive_key_secp256k1(&public_key_element.to_affine(), &tweak).unwrap();

        // then
        insta::assert_json_snapshot!(derived_public_key, {});
    }

    #[test]
    fn test_derive_public_key_edwards_point_ed25519_has_not_changed() {
        // given
        let random_bytes: [u8; 32] = rand::rngs::StdRng::from_seed([42u8; 32]).r#gen();
        let tweak = derive_tweak(&"hello".parse().unwrap(), "my-path");
        let scalar = Scalar::from_bytes_mod_order(random_bytes);
        let public_key_element = Ed25519Group::generator() * scalar;

        // when
        let derived_public_key =
            derive_public_key_edwards_point_ed25519(&public_key_element, &tweak);

        // then
        insta::assert_json_snapshot!(derived_public_key, {});
    }
}
