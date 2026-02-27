use crate::{crypto_shared::types::k256_types, primitives::signature::Tweak, IntoInterfaceType};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
#[cfg(target_arch = "wasm32")]
use k256::EncodedPoint;
use k256::{
    elliptic_curve::{point::AffineCoordinates, CurveArithmetic, PrimeField},
    Secp256k1,
};
use near_account_id::AccountId;
#[cfg(target_arch = "wasm32")]
use near_sdk::env;
use sha3::{Digest, Sha3_256};

use contract_interface::types as dtos;

// Constant prefix that ensures tweak derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const TWEAK_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Tweak {
    let hash: [u8; 32] = derive_from_path(TWEAK_DERIVATION_PREFIX, predecessor_id, path);
    Tweak::new(hash)
}

// Constant prefix that ensures app_id derivation values are used specifically for
// near-mpc with derivation protocol vX.Y.Z.
const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";

pub fn derive_app_id(predecessor_id: &AccountId, derivation_path: &str) -> dtos::CkdAppId {
    let hash: [u8; 32] =
        derive_from_path(APP_ID_DERIVATION_PREFIX, predecessor_id, derivation_path);
    hash.into()
}

// Constant prefix that ensures verify foreign tx derivation values are used specifically for
// near-mpc with derivation protocol vX.Y.Z.
const FOREIGN_TX_TWEAK_DERIVATION_PREFIX: &str =
    "near-mpc-recovery v0.1.0 foreign-tx epsilon derivation:";

pub fn derive_foreign_tx_tweak(predecessor_id: &AccountId, path: &str) -> dtos::Tweak {
    let hash: [u8; 32] = derive_from_path(FOREIGN_TX_TWEAK_DERIVATION_PREFIX, predecessor_id, path);
    dtos::Tweak::from(hash)
}

fn derive_from_path(derivation_prefix: &str, predecessor_id: &AccountId, path: &str) -> [u8; 32] {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the account id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    // Do not reuse this hash function on anything that isn't an account
    // ID or it'll be vulnerable to Hash Malleability/extension attacks.
    let derivation_path = format!("{derivation_prefix}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    hash
}

#[derive(Debug, Clone)]
pub struct TweakNotOnCurve;

pub fn derive_key_secp256k1(
    public_key: &k256_types::PublicKey,
    tweak: &Tweak,
) -> Result<dtos::Secp256k1PublicKey, TweakNotOnCurve> {
    let tweak = k256::Scalar::from_repr(tweak.as_bytes().into())
        .into_option()
        .ok_or(TweakNotOnCurve)?;

    Ok(
        (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * tweak + public_key)
            .to_affine()
            .into_dto_type(),
    )
}

pub fn derive_public_key_edwards_point_ed25519(
    public_key_edwards_point: &curve25519_dalek::EdwardsPoint,
    tweak: &Tweak,
) -> curve25519_dalek::EdwardsPoint {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    public_key_edwards_point + ED25519_BASEPOINT_POINT * tweak
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
    use rand::rngs::OsRng;
    use rand::{Rng, SeedableRng};
    use threshold_signatures::frost::eddsa::KeygenOutput;
    use threshold_signatures::frost_core::keys::SigningShare;
    use threshold_signatures::frost_core::VerifyingKey;
    use threshold_signatures::frost_ed25519::{Ed25519Group, Ed25519Sha512, Group, SigningKey};

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
        let random_bytes: [u8; 32] = rand::thread_rng().gen();

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
    fn test_derive_tweak_has_not_changed() {
        // given
        let account_ids = ["dwefqwg", "qfweqwgwegqw", "fqwerijqw385", "fnwef0942534"];
        let derivation_paths = [
            "frwewegwegweg",
            "fwei2.3f230",
            "f23fjwef8232",
            "fwefwo23fewfw",
        ];

        // when
        let mut tweaks = vec![];
        for account_id in account_ids {
            for derivation_path in derivation_paths {
                let tweak = derive_tweak(&account_id.parse().unwrap(), derivation_path);
                tweaks.push(tweak);
            }
        }

        // then
        insta::assert_json_snapshot!(tweaks, {});
    }

    #[test]
    fn test_derive_app_id_has_not_changed() {
        // given
        let account_ids = ["dwefqwg", "qfweqwgwegqw", "fqwerijqw385", "fnwef0942534"];
        let derivation_paths = [
            "frwewegwegweg",
            "fwei2.3f230",
            "f23fjwef8232",
            "fwefwo23fewfw",
        ];

        // when
        let mut tweaks = vec![];
        for account_id in account_ids {
            for derivation_path in derivation_paths {
                let tweak = derive_tweak(&account_id.parse().unwrap(), derivation_path);
                tweaks.push(tweak);
            }
        }

        // then
        insta::assert_json_snapshot!(tweaks, {});
    }

    #[test]
    fn test_derive_key_secp256k1_has_not_changed() {
        // given
        let random_bytes: [u8; 32] = rand::rngs::StdRng::from_seed([42u8; 32]).gen();
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
        let random_bytes: [u8; 32] = rand::rngs::StdRng::from_seed([42u8; 32]).gen();
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
