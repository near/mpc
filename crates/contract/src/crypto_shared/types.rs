pub mod serializable;

use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    AffinePoint, Secp256k1,
    elliptic_curve::{CurveArithmetic, PrimeField, group::GroupEncoding},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serializable::SerializableEdwardsPoint;

use near_mpc_contract_interface::types as dtos;

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::borsh::BorshSchema)
)]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum PublicKeyExtended {
    Secp256k1 {
        near_public_key: dtos::Secp256k1PublicKey,
    },
    // Invariant: `edwards_point` is always the decompressed representation of `near_public_key_compressed`.
    Ed25519 {
        /// Serialized compressed Edwards-y point.
        near_public_key_compressed: dtos::Ed25519PublicKey,
        /// Decompressed Edwards point used for curve arithmetic operations.
        edwards_point: SerializableEdwardsPoint,
    },
    Bls12381 {
        public_key: dtos::Bls12381G2PublicKey,
    },
}

#[derive(Clone, Debug)]
pub enum PublicKeyExtendedConversionError {
    FailedDecompressingToEdwardsPoint,
}

impl Display for PublicKeyExtendedConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::FailedDecompressingToEdwardsPoint => {
                "The provided compressed key can not be decompressed to an edwards point."
            }
        };

        f.write_str(message)
    }
}

impl From<PublicKeyExtended> for dtos::PublicKey {
    fn from(public_key_extended: PublicKeyExtended) -> Self {
        match public_key_extended {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                dtos::PublicKey::Secp256k1(near_public_key)
            }
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => dtos::PublicKey::Ed25519(near_public_key_compressed),
            PublicKeyExtended::Bls12381 { public_key } => dtos::PublicKey::Bls12381(public_key),
        }
    }
}

impl TryFrom<dtos::PublicKey> for PublicKeyExtended {
    type Error = PublicKeyExtendedConversionError;
    fn try_from(public_key: dtos::PublicKey) -> Result<Self, Self::Error> {
        let extended_key = match public_key {
            dtos::PublicKey::Ed25519(near_public_key_compressed) => {
                let edwards_point =
                    SerializableEdwardsPoint::from_bytes(&near_public_key_compressed)
                        .into_option()
                        .ok_or(
                            PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint,
                        )?;

                Self::Ed25519 {
                    near_public_key_compressed,
                    edwards_point,
                }
            }
            dtos::PublicKey::Secp256k1(near_public_key) => Self::Secp256k1 { near_public_key },
            dtos::PublicKey::Bls12381(public_key) => Self::Bls12381 { public_key },
        };

        Ok(extended_key)
    }
}

pub mod k256_types {
    use super::{
        AffinePoint, BorshDeserialize, BorshSerialize, CurveArithmetic, Deserialize, PrimeField,
        Secp256k1, Serialize,
    };
    use k256::Scalar;

    pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

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

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SerializableAffinePoint {
        pub affine_point: AffinePoint,
    }

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
    use super::{BorshDeserialize, BorshSerialize, Deserialize, PrimeField, Serialize, serde_as};
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
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
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
    #[case::secp256k1(
        "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd"
            .parse::<dtos::PublicKey>()
            .unwrap()
    )]
    #[case::ed25519(
        "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
            .parse::<dtos::PublicKey>()
            .unwrap()
    )]
    #[case::bls12381(dtos::PublicKey::Bls12381(dtos::Bls12381G2PublicKey([7u8; 96])))]
    fn test_serialization_of_public_key_extended(#[case] public_key: dtos::PublicKey) {
        let public_key_extended = PublicKeyExtended::try_from(public_key).unwrap();
        let mut buffer: Vec<u8> = vec![];
        BorshSerialize::serialize(&public_key_extended, &mut buffer).unwrap();

        let mut slice_ref = &buffer[..];
        let deserialized =
            <PublicKeyExtended as BorshDeserialize>::deserialize(&mut slice_ref).unwrap();

        assert_eq!(deserialized, public_key_extended);
    }

    #[test]
    fn public_key_extended_try_from_public_key__should_reject_a_non_curve_ed25519_key() {
        // Given a 32-byte value whose y-coordinate has no corresponding x on the curve.
        let public_key = dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey([2u8; 32]));

        // When
        let result = PublicKeyExtended::try_from(public_key);

        // Then
        assert_matches!(
            result,
            Err(PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint)
        );
    }
}
