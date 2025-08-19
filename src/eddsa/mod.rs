//! This module serves as a wrapper for Ed25519 scheme.
pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_ed25519::keys::SigningShare;
use frost_ed25519::{Ed25519Sha512, VerifyingKey};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key: VerifyingKey,
}

impl From<crate::generic_dkg::KeygenOutput<Ed25519Sha512>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Ed25519Sha512>) -> Self {
        Self {
            private_share: value.private_share,
            public_key: value.public_key,
        }
    }
}

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}
