//! This module serves as a wrapper for Frost protocol.
use frost_core::keys::{PublicKeyPackage, SigningShare};
use crate::generic_dkg::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_ed25519::Ed25519Sha512;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeygenOutput {
    pub private_share: SigningShare<Ed25519Sha512>,
    pub public_key_package: PublicKeyPackage<Ed25519Sha512>,
}

impl From<crate::generic_dkg::KeygenOutput<Ed25519Sha512>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Ed25519Sha512>) -> Self {
        Self {
            private_share: value.private_share,
            public_key_package: value.public_key_package,
        }
    }
}

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}

pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;
mod kdf;

pub use kdf::derive_keygen_output;


