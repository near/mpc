//! This module serves as a wrapper for Frost protocol.

use crate::generic_dkg::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_secp256k1::keys::SigningShare;
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key: VerifyingKey,
}

impl From<crate::generic_dkg::KeygenOutput<Secp256K1Sha256>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Secp256K1Sha256>) -> Self {
        Self {
            private_share: value.private_share,
            public_key: value.public_key,
        }
    }
}

impl ScalarSerializationFormat for Secp256K1Sha256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::BigEndian
    }
}

impl Ciphersuite for Secp256K1Sha256 {}

pub mod dkg_ecdsa;
pub mod math;
pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;
pub mod triples;
