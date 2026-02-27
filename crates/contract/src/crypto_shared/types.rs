pub mod serializable;

use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    elliptic_curve::{group::GroupEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Secp256k1,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
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
    use super::*;
    use k256::Scalar;

    pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        derive(::near_sdk::schemars::JsonSchema)
    )]
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Ord, PartialOrd)]
    pub struct SerializableScalar {
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "String"), // Scalar is a U256, which becomes a HEX-string after serialization.
        )]
        pub scalar: Scalar,
    }

    impl SerializableScalar {
        pub fn new(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl From<Scalar> for SerializableScalar {
        fn from(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    // Is there a better way to enforce `borsh` serialization?
    impl BorshSerialize for SerializableScalar {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: [u8; 32] = self.scalar.to_bytes().into();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar =
                Scalar::from_repr(from_ser.into())
                    .into_option()
                    .ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "The given scalar is not in the field of Secp256k1",
                    ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        derive(::near_sdk::schemars::JsonSchema)
    )]
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SerializableAffinePoint {
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>"), // Affine point may be compressed or decompressed.
        )]
        pub affine_point: AffinePoint,
    }

    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        derive(::near_sdk::schemars::JsonSchema)
    )]
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub struct Signature {
        pub big_r: SerializableAffinePoint,
        pub s: SerializableScalar,
        pub recovery_id: u8,
    }

    impl Signature {
        pub fn new(big_r: AffinePoint, s: k256::Scalar, recovery_id: u8) -> Self {
            Signature {
                big_r: SerializableAffinePoint {
                    affine_point: big_r,
                },
                s: s.into(),
                recovery_id,
            }
        }
    }
}

pub mod ed25519_types {
    use super::*;
    use curve25519_dalek::Scalar;

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
    pub struct SerializableScalar {
        scalar: Scalar,
    }

    impl SerializableScalar {
        pub fn new(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl From<Scalar> for SerializableScalar {
        fn from(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl BorshSerialize for SerializableScalar {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: [u8; 32] = self.scalar.to_bytes();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar = Scalar::from_repr(from_ser)
                .into_option()
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "The given scalar is not in the field of ed25519",
                ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    impl Ord for SerializableScalar {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.scalar.as_bytes().cmp(other.scalar.as_bytes())
        }
    }

    impl PartialOrd for SerializableScalar {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        derive(::near_sdk::schemars::JsonSchema)
    )]
    #[serde_as]
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct Signature(
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>") // Schemars doesn't support arrays of size greater than 32. 
        )]
        #[serde_as(as = "[_; 64]")]
        [u8; 64],
    );

    impl Signature {
        pub fn as_bytes(&self) -> &[u8; 64] {
            &self.0
        }

        pub fn new(bytes: [u8; 64]) -> Self {
            Self(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::PrimeField;
    use rstest::rstest;

    #[test]
    fn serializeable_scalar_roundtrip() {
        let test_vec = vec![
            k256::Scalar::ZERO,
            k256::Scalar::ONE,
            k256::Scalar::from_u128(u128::MAX),
            k256::Scalar::from_repr([3; 32].into()).unwrap(),
        ];

        for scalar in test_vec.into_iter() {
            let input = k256_types::SerializableScalar { scalar };
            // Test borsh
            {
                let serialized = borsh::to_vec(&input).unwrap();
                let output: k256_types::SerializableScalar =
                    borsh::from_slice(&serialized).unwrap();
                assert_eq!(input, output, "Failed on {:?}", scalar);
            }
        }
    }

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
