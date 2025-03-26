//! Key Derivation Function for Frost keys.
//!
//! The general idea is that we have a `tweak` – some value, e.g. associated with a user.
//! This value can be translated into Field scalar.
//! Then the mapping functions are following:
//! ```
//! secret_key' = kdf(secret_key, tweak) = secret_key + tweak
//! public_key' = kdf(public_key) = public_key + G * tweak
//! ```
//! Where G – group generator.
//!
//! Both for `KeyPackage` and `PublicKeyPackage` struct consist of some kind of helper objects
//! like "verifying shares"/"verifying keys" etc. We have to do derivation for them and construct new objects.
use crate::eddsa;
use curve25519_dalek::Scalar;
use crate::KeygenOutput;
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost_ed25519::{Ed25519Group, Group, Identifier, VerifyingKey};
use std::collections::BTreeMap;

pub(crate) fn derive_keygen_output(keygen_output: &KeygenOutput, tweak: [u8; 32]) -> KeygenOutput {
    let tweak = Scalar::from_bytes_mod_order(tweak);
    KeygenOutput {
        key_package: derive_key_package(&keygen_output.key_package, tweak),
        public_key_package: derive_public_key_package(&keygen_output.public_key_package, tweak),
    }
}

fn derive_public_key_package(pubkey_package: &PublicKeyPackage, tweak: Scalar) -> PublicKeyPackage {
    let verifying_shares: BTreeMap<Identifier, VerifyingShare> = pubkey_package
        .verifying_shares()
        .iter()
        .map(|(&identifier, &share)| {
            (
                identifier,
                VerifyingShare::new(add_tweak(share.to_element(), tweak)),
            )
        })
        .collect();
    let verifying_key = VerifyingKey::new(add_tweak(
        pubkey_package.verifying_key().to_element(),
        tweak,
    ));
    PublicKeyPackage::new(verifying_shares, verifying_key)
}

fn derive_key_package(key_package: &KeyPackage, tweak: Scalar) -> KeyPackage {
    KeyPackage::new(
        *key_package.identifier(),
        SigningShare::new(key_package.signing_share().to_scalar() + tweak),
        VerifyingShare::new(add_tweak(key_package.verifying_share().to_element(), tweak)),
        VerifyingKey::new(add_tweak(key_package.verifying_key().to_element(), tweak)),
        *key_package.min_signers(),
    )
}

fn add_tweak(
    point: curve25519_dalek::EdwardsPoint,
    tweak: Scalar,
) -> curve25519_dalek::EdwardsPoint {
    point + Ed25519Group::generator() * tweak
}

#[cfg(test)]
mod tests {
    use crate::frost::kdf::derive_keygen_output;
    use crate::frost::tests::{build_key_packages_with_dealer, reconstruct_signing_key};
    use aes_gcm::aead::rand_core::RngCore;
    use rand::rngs::OsRng;

    #[test]
    fn proof_of_concept() -> Result<(), anyhow::Error> {
        let max_signers = 9;
        let min_signers = 6;

        let mut tweak = [0u8; 32];
        OsRng.fill_bytes(&mut tweak);

        let participants = build_key_packages_with_dealer(max_signers, min_signers)
            .into_iter()
            .map(|(participant, key_pair)| (participant, derive_keygen_output(&key_pair, tweak)))
            .collect::<Vec<_>>();

        let verifying_key = *participants
            .first()
            .unwrap()
            .1
            .public_key_package
            .verifying_key();

        let signing_key = reconstruct_signing_key(participants.as_slice())?;

        let mut message = [0u8; 32];
        OsRng.fill_bytes(&mut message);

        let signature = signing_key.sign(OsRng, message.as_slice());
        verifying_key.verify(message.as_slice(), &signature)?;

        Ok(())
    }
}
