use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::EdwardsPoint;
use k256::{
    elliptic_curve::{group::GroupEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Secp256k1,
};
use near_sdk::near;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "scheme")]
pub enum SignatureResponse {
    Secp256k1(k256_types::Signature),
    Ed25519 { signature: ed25519_types::Signature },
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum PublicKeyExtended {
    Secp256k1 {
        near_public_key: near_sdk::PublicKey,
    },
    Ed25519 {
        near_public_key: near_sdk::PublicKey,
        edwards_point: EdwardsPoint,
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

impl From<PublicKeyExtended> for near_sdk::PublicKey {
    fn from(public_key_extended: PublicKeyExtended) -> Self {
        match public_key_extended {
            PublicKeyExtended::Secp256k1 { near_public_key } => near_public_key,
            PublicKeyExtended::Ed25519 {
                near_public_key, ..
            } => near_public_key,
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

                let edwards_point = curve25519_dalek::EdwardsPoint::from_bytes(public_key_bytes)
                    .into_option()
                    .ok_or(PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint)?;

                Self::Ed25519 {
                    near_public_key,
                    edwards_point,
                }
            }
            near_sdk::CurveType::SECP256K1 => Self::Secp256k1 { near_public_key },
        };

        Ok(extended_key)
    }
}

mod serialize {
    use super::*;

    #[near(serializers=[borsh, json])]
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub enum PublicKeyExtendedHelper {
        Secp256k1 {
            key: near_sdk::PublicKey,
        },
        Ed25519 {
            key: near_sdk::PublicKey,
            edwards_point: SerializableEdwardsPoint,
        },
    }

    impl From<PublicKeyExtended> for PublicKeyExtendedHelper {
        fn from(value: PublicKeyExtended) -> Self {
            match value {
                PublicKeyExtended::Secp256k1 {
                    near_public_key: key,
                } => Self::Secp256k1 { key },
                PublicKeyExtended::Ed25519 {
                    near_public_key: key,
                    edwards_point,
                } => Self::Ed25519 {
                    key,
                    edwards_point: SerializableEdwardsPoint(edwards_point),
                },
            }
        }
    }

    impl From<PublicKeyExtendedHelper> for PublicKeyExtended {
        fn from(value: PublicKeyExtendedHelper) -> Self {
            match value {
                PublicKeyExtendedHelper::Secp256k1 { key } => Self::Secp256k1 {
                    near_public_key: key,
                },
                PublicKeyExtendedHelper::Ed25519 { key, edwards_point } => Self::Ed25519 {
                    near_public_key: key,
                    edwards_point: edwards_point.0,
                },
            }
        }
    }

    impl PublicKeyExtended {
        pub fn near_public_key(self) -> near_sdk::PublicKey {
            match self {
                PublicKeyExtended::Secp256k1 {
                    near_public_key: key,
                } => key,
                PublicKeyExtended::Ed25519 {
                    near_public_key: key,
                    ..
                } => key,
            }
        }
    }

    impl BorshSerialize for PublicKeyExtended {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let helper_representation: PublicKeyExtendedHelper = self.clone().into();
            let to_ser: Vec<u8> = serde_json::to_vec(&helper_representation)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for PublicKeyExtended {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let public_key_extended: PublicKeyExtendedHelper = serde_json::from_slice(&from_ser)?;
            Ok(public_key_extended.into())
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Clone, Copy)]
    pub struct SerializableEdwardsPoint(EdwardsPoint);

    impl BorshSerialize for SerializableEdwardsPoint {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: Vec<u8> = serde_json::to_vec(&self.0)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableEdwardsPoint {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let edwards_point = serde_json::from_slice(&from_ser)?;
            Ok(SerializableEdwardsPoint(edwards_point))
        }
    }
}

pub mod k256_types {
    use super::*;
    use k256::Scalar;

    pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Ord, PartialOrd)]
    pub struct SerializableScalar {
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

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SerializableAffinePoint {
        pub affine_point: AffinePoint,
    }

    impl BorshSerialize for SerializableAffinePoint {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: Vec<u8> = serde_json::to_vec(&self.affine_point)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableAffinePoint {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let affine_point = serde_json::from_slice(&from_ser)?;
            Ok(SerializableAffinePoint { affine_point })
        }
    }
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
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

    #[serde_as]
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct Signature(#[serde_as(as = "[_; 64]")] [u8; 64]);

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
mod test {
    use super::*;

    #[test]
    fn serializeable_scalar_roundtrip() {
        use k256::elliptic_curve::PrimeField;
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
}
