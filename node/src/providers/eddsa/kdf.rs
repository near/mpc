//! Key Derivation Function for eddsa keys.
use cait_sith::eddsa::KeygenOutput;
use cait_sith::frost_ed25519::keys::SigningShare;
use cait_sith::frost_ed25519::{Ed25519Group, Group, VerifyingKey};
use curve25519_dalek::Scalar;

pub(crate) fn derive_keygen_output(keygen_output: &KeygenOutput, tweak: [u8; 32]) -> KeygenOutput {
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
