//! Key Derivation Function for Frost keys.
//!
//! The general idea is that we have a `tweak` – some value, e.g. associated with a user.
//! This value can be translated into Field scalar.
//! Then the mapping functions are following:
//!
//! secret_key' = kdf(secret_key, tweak) = secret_key + tweak
//! public_key' = kdf(public_key) = public_key + G * tweak
//!
//! Where G – group generator.
//!
//! Both for `KeyPackage` and `PublicKeyPackage` struct consist of some kind of helper objects
//! like "verifying shares"/"verifying keys" etc. We have to do derivation for them and construct new objects.
use crate::eddsa::KeygenOutput;
use frost_core::Field;
use frost_ed25519::keys::{PublicKeyPackage, SigningShare, VerifyingShare};
use frost_ed25519::{Ed25519Group, Ed25519ScalarField, Group, Identifier, VerifyingKey};
use std::collections::BTreeMap;

pub fn derive_keygen_output(keygen_output: &KeygenOutput, tweak: [u8; 32]) -> KeygenOutput {
    let tweak = <Ed25519ScalarField as Field>::Scalar::from_bytes_mod_order(tweak);
    KeygenOutput {
        private_share: SigningShare::new(keygen_output.private_share.to_scalar() + tweak),
        public_key_package: derive_public_key_package(&keygen_output.public_key_package, tweak),
    }
}

fn derive_public_key_package(
    pubkey_package: &PublicKeyPackage,
    tweak: <Ed25519ScalarField as Field>::Scalar,
) -> PublicKeyPackage {
    let verifying_shares: BTreeMap<Identifier, VerifyingShare> = pubkey_package
        .verifying_shares()
        .iter()
        .map(|(&identifier, &share)| {
            (
                identifier,
                VerifyingShare::new(share.to_element() + Ed25519Group::generator() * tweak),
            )
        })
        .collect();
    let verifying_key = VerifyingKey::new(
        pubkey_package.verifying_key().to_element() + Ed25519Group::generator() * tweak,
    );
    PublicKeyPackage::new(verifying_shares, verifying_key)
}
