//! Small conversion helpers between types used in tests (e.g.
//! [`ed25519_dalek::SigningKey`]) and their `near_kit` counterparts.
//!
//! Grouped into one module so they are easy to find and relocate later.

use ed25519_dalek::SigningKey;

/// Extract the public half of `key` as a [`near_kit::PublicKey`].
pub fn signing_key_to_near_public_key(key: &SigningKey) -> near_kit::PublicKey {
    near_kit::PublicKey::Ed25519(key.verifying_key().to_bytes())
}

/// Convert `key` into a [`near_kit::SecretKey`].
pub fn signing_key_to_near_secret_key(key: &SigningKey) -> near_kit::SecretKey {
    near_kit::SecretKey::Ed25519(key.to_bytes())
}
