//! This module serves as a wrapper for Frost protocol.

use crate::generic_dkg::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_secp256k1::*;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use crate::CSCurve;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenOutput<C: CSCurve> {
    pub private_share: C::Scalar,
    pub public_key: C::AffinePoint,
}

impl From<crate::generic_dkg::KeygenOutput<Secp256K1Sha256>> for KeygenOutput<Secp256k1> {
    fn from(value: crate::generic_dkg::KeygenOutput<Secp256K1Sha256>) -> Self {
        Self {
            private_share: value.private_share.to_scalar(),
            public_key: value.public_key_package.verifying_key().to_element().into(),
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
