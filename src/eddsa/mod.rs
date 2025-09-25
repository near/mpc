//! This module serves as a wrapper for Ed25519 scheme.
pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_ed25519::Ed25519Sha512;

pub type KeygenOutput = crate::KeygenOutput<Ed25519Sha512>;

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}

/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<frost_ed25519::Signature>;
