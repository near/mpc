pub mod serializable;

use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use k256::elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Serialize};
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::assert_matches;

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
