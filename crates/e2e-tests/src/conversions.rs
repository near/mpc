//! Small conversion helpers between types used in tests (e.g.
//! [`ed25519_dalek::SigningKey`]) and their `near_kit` counterparts.
//!
//! Grouped into one module so they are easy to find and relocate later.

use ed25519_dalek::SigningKey;

pub trait ToNearKey {
    fn to_near_public_key(&self) -> near_kit::PublicKey;
    fn to_near_secret_key(&self) -> near_kit::SecretKey;
}

impl ToNearKey for SigningKey {
    fn to_near_public_key(&self) -> near_kit::PublicKey {
        near_kit::PublicKey::Ed25519(self.verifying_key().to_bytes())
    }

    fn to_near_secret_key(&self) -> near_kit::SecretKey {
        near_kit::SecretKey::Ed25519(self.to_bytes())
    }
}
