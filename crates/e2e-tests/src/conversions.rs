//! Small conversion helpers between types used in tests (e.g.
//! [`ed25519_dalek::SigningKey`]) and their `near_kit` counterparts.
//!
//! Grouped into one module so they are easy to find and relocate later.

use ed25519_dalek::SigningKey;

pub trait ToNearKey {
    fn to_near_public_key(&self) -> near_kit::signer::PublicKey;
    fn to_near_secret_key(&self) -> near_kit::signer::SecretKey;
}

impl ToNearKey for SigningKey {
    fn to_near_public_key(&self) -> near_kit::signer::PublicKey {
        near_kit::signer::PublicKey::ed25519_from_bytes(self.verifying_key().to_bytes())
            .expect("an ed25519_dalek verifying key is always a valid curve point")
    }

    fn to_near_secret_key(&self) -> near_kit::signer::SecretKey {
        near_kit::signer::SecretKey::ed25519_from_bytes(self.to_bytes())
    }
}
