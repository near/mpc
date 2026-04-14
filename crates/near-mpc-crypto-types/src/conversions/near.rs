use super::CryptoConversionError;
use crate::crypto::{Ed25519PublicKey, PublicKey, PublicKeyExtended, Secp256k1PublicKey};
use crate::primitives::K256Signature;

impl From<&near_sdk::PublicKey> for PublicKey {
    fn from(pk: &near_sdk::PublicKey) -> Self {
        match pk.curve_type() {
            near_sdk::CurveType::SECP256K1 => {
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(&pk.as_bytes()[1..]);
                PublicKey::Secp256k1(Secp256k1PublicKey::from(bytes))
            }
            near_sdk::CurveType::ED25519 => {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&pk.as_bytes()[1..]);
                PublicKey::Ed25519(Ed25519PublicKey::from(bytes))
            }
        }
    }
}

impl TryFrom<PublicKey> for near_sdk::PublicKey {
    type Error = CryptoConversionError;
    fn try_from(pk: PublicKey) -> Result<Self, Self::Error> {
        match pk {
            PublicKey::Secp256k1(inner) => Ok(near_sdk::PublicKey::from(inner)),
            PublicKey::Ed25519(inner) => Ok(near_sdk::PublicKey::from(inner)),
            PublicKey::Bls12381(_) => Err(CryptoConversionError::UnsupportedCurve),
        }
    }
}

impl From<Ed25519PublicKey> for near_sdk::PublicKey {
    fn from(pk: Ed25519PublicKey) -> Self {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, pk.0.into())
            .expect("Ed25519PublicKey always has correct size")
    }
}

impl TryFrom<&near_sdk::PublicKey> for Ed25519PublicKey {
    type Error = CryptoConversionError;
    fn try_from(pk: &near_sdk::PublicKey) -> Result<Self, Self::Error> {
        match pk.curve_type() {
            near_sdk::CurveType::ED25519 => {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&pk.as_bytes()[1..]);
                Ok(Ed25519PublicKey::from(bytes))
            }
            _ => Err(CryptoConversionError::UnsupportedCurve),
        }
    }
}

impl From<Secp256k1PublicKey> for near_sdk::PublicKey {
    fn from(pk: Secp256k1PublicKey) -> Self {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, pk.0.into())
            .expect("Secp256k1PublicKey always has correct size")
    }
}

impl TryFrom<&near_sdk::PublicKey> for Secp256k1PublicKey {
    type Error = CryptoConversionError;
    fn try_from(pk: &near_sdk::PublicKey) -> Result<Self, Self::Error> {
        match pk.curve_type() {
            near_sdk::CurveType::SECP256K1 => {
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(&pk.as_bytes()[1..]);
                Ok(Secp256k1PublicKey::from(bytes))
            }
            _ => Err(CryptoConversionError::UnsupportedCurve),
        }
    }
}

impl TryFrom<PublicKeyExtended> for PublicKey {
    type Error = CryptoConversionError;
    fn try_from(pk: PublicKeyExtended) -> Result<Self, Self::Error> {
        match pk {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                let near_pk: near_sdk::PublicKey = near_public_key
                    .parse()
                    .map_err(|_| CryptoConversionError::InvalidPublicKey)?;
                Ok(PublicKey::from(&near_pk))
            }
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => {
                let near_pk: near_sdk::PublicKey = near_public_key_compressed
                    .parse()
                    .map_err(|_| CryptoConversionError::InvalidPublicKey)?;
                Ok(PublicKey::from(&near_pk))
            }
            PublicKeyExtended::Bls12381 { public_key } => Ok(public_key),
        }
    }
}

impl From<PublicKey> for PublicKeyExtended {
    fn from(pk: PublicKey) -> Self {
        match pk {
            PublicKey::Secp256k1(inner) => PublicKeyExtended::Secp256k1 {
                near_public_key: String::from(&inner),
            },
            PublicKey::Ed25519(inner) => PublicKeyExtended::Ed25519 {
                near_public_key_compressed: String::from(&inner),
                edwards_point: inner.0,
            },
            PublicKey::Bls12381(inner) => PublicKeyExtended::Bls12381 {
                public_key: PublicKey::Bls12381(inner),
            },
        }
    }
}

impl TryFrom<&PublicKeyExtended> for near_sdk::PublicKey {
    type Error = CryptoConversionError;
    fn try_from(pk: &PublicKeyExtended) -> Result<Self, Self::Error> {
        match pk {
            PublicKeyExtended::Secp256k1 { near_public_key } => near_public_key
                .parse()
                .map_err(|_| CryptoConversionError::InvalidPublicKey),
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => near_public_key_compressed
                .parse()
                .map_err(|_| CryptoConversionError::InvalidPublicKey),
            PublicKeyExtended::Bls12381 { .. } => Err(CryptoConversionError::UnsupportedCurve),
        }
    }
}

impl K256Signature {
    /// Returns the 64-byte `r || s` representation compatible with NEAR's `ecrecover`.
    ///
    /// `r` is the x-coordinate extracted from the compressed R point (`big_r`),
    /// and `s` is the scalar bytes.
    pub fn to_ecrecover_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.big_r.affine_point[1..]);
        bytes[32..].copy_from_slice(&self.s.scalar);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Bls12381G2PublicKey;
    use assert_matches::assert_matches;

    #[test]
    fn roundtrip_ed25519_public_key() {
        // given
        let near_pk: near_sdk::PublicKey = "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv"
            .parse()
            .unwrap();

        // when
        let dto = Ed25519PublicKey::try_from(&near_pk).unwrap();
        let recovered = near_sdk::PublicKey::from(dto);

        // then
        assert_eq!(near_pk, recovered);
    }

    #[test]
    fn roundtrip_secp256k1_public_key() {
        // given
        let near_pk: near_sdk::PublicKey =
            "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd"
                .parse().unwrap();

        // when
        let dto = Secp256k1PublicKey::try_from(&near_pk).unwrap();
        let recovered = near_sdk::PublicKey::from(dto);

        // then
        assert_eq!(near_pk, recovered);
    }

    #[test]
    fn roundtrip_public_key_enum_ed25519() {
        // given
        let near_pk: near_sdk::PublicKey = "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv"
            .parse()
            .unwrap();

        // when
        let dto = PublicKey::from(&near_pk);
        let recovered = near_sdk::PublicKey::try_from(dto).unwrap();

        // then
        assert_eq!(near_pk, recovered);
    }

    #[test]
    fn roundtrip_public_key_enum_secp256k1() {
        // given
        let near_pk: near_sdk::PublicKey =
            "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd"
                .parse().unwrap();

        // when
        let dto = PublicKey::from(&near_pk);
        let recovered = near_sdk::PublicKey::try_from(dto).unwrap();

        // then
        assert_eq!(near_pk, recovered);
    }

    #[test]
    fn bls12381_public_key_to_near_is_rejected() {
        // given
        let dto = PublicKey::Bls12381(Bls12381G2PublicKey::from([0u8; 96]));

        // when
        let result = near_sdk::PublicKey::try_from(dto);

        // then
        assert_matches!(result, Err(CryptoConversionError::UnsupportedCurve));
    }

    #[test]
    fn secp256k1_near_pk_to_ed25519_dto_is_rejected() {
        // given
        let near_pk: near_sdk::PublicKey =
            "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd"
                .parse().unwrap();

        // when
        let result = Ed25519PublicKey::try_from(&near_pk);

        // then
        assert_matches!(result, Err(CryptoConversionError::UnsupportedCurve));
    }

    #[test]
    fn ed25519_near_pk_to_secp256k1_dto_is_rejected() {
        // given
        let near_pk: near_sdk::PublicKey = "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv"
            .parse()
            .unwrap();

        // when
        let result = Secp256k1PublicKey::try_from(&near_pk);

        // then
        assert_matches!(result, Err(CryptoConversionError::UnsupportedCurve));
    }

    #[test]
    fn test_assert_near_public_key_sizes() {
        const ED25519_PUBLIC_KEY_SIZE: usize = 32;
        const SECP256K1_PUBLIC_KEY_SIZE: usize = 64;

        let near_public_keys = [
            "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd",
            "secp256k1:3Abs6NwUMErNAftRfipRjWxxqcTPBJTSr2uoHi3bHcthzb4iXqNnNYi86ATKwf4XWHg1JDrX2m1sJgNMYq7ey6cG",
            "secp256k1:21C8NARZw2tUuULi1tENKi5azgDKLp9cv4FT2U1N6iF5k1W33BbJvsLr6rCZsYZxxUjBtpuWCsKvmv9P5ARzyyyn",
            "secp256k1:4YbU8ZLEQK7gww1f65ZhtFCYfSxrm67sV9eaQi8oRo1LvCAtznztsiryJrzHg2oz285xN3ADAsGPizmCNe4hn9WR",
            "ed25519:2XPuwqhg71RXRiTUMKGapd8FYWgXnxVvydYBK9tS1ex2",
            "ed25519:4upBpJYUrjPBzqNYaY8pvJGQtep7YMT3j9zRsopYQqfG",
            "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv",
            "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k",
        ];
        for pk in near_public_keys {
            let near_pk: near_sdk::PublicKey = pk.parse().unwrap();
            match near_pk.curve_type() {
                near_sdk::CurveType::ED25519 => {
                    assert_eq!(near_pk.as_bytes().len(), ED25519_PUBLIC_KEY_SIZE + 1);
                }
                near_sdk::CurveType::SECP256K1 => {
                    assert_eq!(near_pk.as_bytes().len(), SECP256K1_PUBLIC_KEY_SIZE + 1);
                }
            }
        }
    }

    #[test]
    fn test_assert_near_public_key_serde_equivalence() {
        let public_keys = [
            "secp256k1:4Ls3DBDeFDaf5zs2hxTBnJpKnfsnjNahpKU9HwQvij8fTXoCP9y5JQqQpe273WgrKhVVj1EH73t5mMJKDFMsxoEd",
            "secp256k1:3Abs6NwUMErNAftRfipRjWxxqcTPBJTSr2uoHi3bHcthzb4iXqNnNYi86ATKwf4XWHg1JDrX2m1sJgNMYq7ey6cG",
            "secp256k1:21C8NARZw2tUuULi1tENKi5azgDKLp9cv4FT2U1N6iF5k1W33BbJvsLr6rCZsYZxxUjBtpuWCsKvmv9P5ARzyyyn",
            "secp256k1:4YbU8ZLEQK7gww1f65ZhtFCYfSxrm67sV9eaQi8oRo1LvCAtznztsiryJrzHg2oz285xN3ADAsGPizmCNe4hn9WR",
            "ed25519:2XPuwqhg71RXRiTUMKGapd8FYWgXnxVvydYBK9tS1ex2",
            "ed25519:4upBpJYUrjPBzqNYaY8pvJGQtep7YMT3j9zRsopYQqfG",
            "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv",
            "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k",
        ];
        for pk in public_keys {
            let near_pk: near_sdk::PublicKey = pk.parse().unwrap();
            let dtos_pk: PublicKey = pk.parse().unwrap();
            let near_pk_ser = serde_json::to_string(&near_pk).unwrap();
            let dtos_pk_ser = serde_json::to_string(&dtos_pk).unwrap();
            assert_eq!(near_pk_ser, dtos_pk_ser);
            assert_eq!(format!("\"{pk}\""), dtos_pk_ser);

            match (near_pk.curve_type(), dtos_pk) {
                (near_sdk::CurveType::ED25519, PublicKey::Ed25519(inner)) => {
                    assert_eq!(*inner, near_pk.as_bytes()[1..]);
                }
                (near_sdk::CurveType::SECP256K1, PublicKey::Secp256k1(inner)) => {
                    assert_eq!(*inner, near_pk.as_bytes()[1..]);
                }
                _ => unreachable!(),
            }
        }
    }
}
