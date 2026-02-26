pub mod serializable;

use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use k256::elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Serialize};
use serializable::SerializableEdwardsPoint;

use crate::{errors, IntoContractType, IntoInterfaceType};
use contract_interface::types as dtos;

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CKDResponse {
    pub big_y: dtos::Bls12381G1PublicKey,
    pub big_c: dtos::Bls12381G1PublicKey,
}

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema),
    derive(::borsh::BorshSchema)
)]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum PublicKeyExtended {
    Secp256k1 {
        near_public_key: near_sdk::PublicKey,
    },
    // Invariant: `edwards_point` is always the decompressed representation of `near_public_key_compressed`.
    Ed25519 {
        /// Serialized compressed Edwards-y point.
        near_public_key_compressed: near_sdk::PublicKey,
        /// Decompressed Edwards point used for curve arithmetic operations.
        edwards_point: SerializableEdwardsPoint,
    },
    Bls12381 {
        public_key: dtos::PublicKey,
    },
}

#[derive(Clone, Debug)]
pub enum PublicKeyExtendedConversionError {
    PublicKeyLengthMalformed,
    FailedDecompressingToEdwardsPoint,
}

impl Display for PublicKeyExtendedConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::PublicKeyLengthMalformed => "Provided public key has malformed length.",
            Self::FailedDecompressingToEdwardsPoint => {
                "The provided compressed key can not be decompressed to an edwards point."
            }
        };

        f.write_str(message)
    }
}

impl TryFrom<PublicKeyExtended> for near_sdk::PublicKey {
    type Error = errors::Error;
    fn try_from(public_key_extended: PublicKeyExtended) -> Result<Self, Self::Error> {
        match public_key_extended {
            PublicKeyExtended::Secp256k1 { near_public_key } => Ok(near_public_key),
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => Ok(near_public_key_compressed),
            PublicKeyExtended::Bls12381 { public_key: _ } => {
                Err(errors::ConversionError::DataConversion
                    .message("Cannot convert Bls12381 key to near_sdk::PublicKey"))?
            }
        }
    }
}

impl From<PublicKeyExtended> for dtos::PublicKey {
    fn from(public_key_extended: PublicKeyExtended) -> Self {
        match public_key_extended {
            PublicKeyExtended::Secp256k1 { near_public_key } => near_public_key.into_dto_type(),
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => near_public_key_compressed.into_dto_type(),
            PublicKeyExtended::Bls12381 { public_key } => public_key,
        }
    }
}

impl TryFrom<near_sdk::PublicKey> for PublicKeyExtended {
    type Error = PublicKeyExtendedConversionError;
    fn try_from(near_public_key: near_sdk::PublicKey) -> Result<Self, Self::Error> {
        let extended_key = match near_public_key.curve_type() {
            near_sdk::CurveType::ED25519 => {
                let public_key_bytes: &[u8; 32] = near_public_key
                    .as_bytes()
                    .get(1..)
                    .map(TryInto::try_into)
                    .ok_or(PublicKeyExtendedConversionError::PublicKeyLengthMalformed)?
                    .map_err(|_| PublicKeyExtendedConversionError::PublicKeyLengthMalformed)?;

                let edwards_point = SerializableEdwardsPoint::from_bytes(public_key_bytes)
                    .into_option()
                    .ok_or(PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint)?;

                Self::Ed25519 {
                    near_public_key_compressed: near_public_key,
                    edwards_point,
                }
            }
            near_sdk::CurveType::SECP256K1 => Self::Secp256k1 { near_public_key },
        };

        Ok(extended_key)
    }
}

impl TryFrom<dtos::PublicKey> for PublicKeyExtended {
    type Error = PublicKeyExtendedConversionError;
    fn try_from(public_key: dtos::PublicKey) -> Result<Self, Self::Error> {
        let extended_key = match public_key {
            dtos::PublicKey::Ed25519(inner_public_key) => {
                let near_public_key = inner_public_key.into_contract_type();
                let public_key_bytes: &[u8; 32] = near_public_key
                    .as_bytes()
                    .get(1..)
                    .map(TryInto::try_into)
                    .ok_or(PublicKeyExtendedConversionError::PublicKeyLengthMalformed)?
                    .map_err(|_| PublicKeyExtendedConversionError::PublicKeyLengthMalformed)?;

                let edwards_point = SerializableEdwardsPoint::from_bytes(public_key_bytes)
                    .into_option()
                    .ok_or(PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint)?;

                Self::Ed25519 {
                    near_public_key_compressed: near_public_key,
                    edwards_point,
                }
            }
            dtos::PublicKey::Secp256k1(inner_public_key) => {
                let near_public_key = inner_public_key.into_contract_type();
                Self::Secp256k1 { near_public_key }
            }
            dtos::PublicKey::Bls12381(inner_public_key) => Self::Bls12381 {
                public_key: dtos::PublicKey::from(inner_public_key),
            },
        };

        Ok(extended_key)
    }
}

pub mod k256_types {
    use k256::{elliptic_curve::CurveArithmetic, Secp256k1};

    pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Tests the serialization and deserialization of [`PublicKeyExtended`] works.
    #[rstest]
    #[case("secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd")]
    #[case("ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp")]
    fn test_serialization_of_public_key_extended(#[case] near_public_key: near_sdk::PublicKey) {
        let public_key_extended = PublicKeyExtended::try_from(near_public_key).unwrap();
        let mut buffer: Vec<u8> = vec![];
        BorshSerialize::serialize(&public_key_extended, &mut buffer).unwrap();

        let mut slice_ref = &buffer[..];
        let deserialized =
            <PublicKeyExtended as BorshDeserialize>::deserialize(&mut slice_ref).unwrap();

        assert_eq!(deserialized, public_key_extended);
    }
}
