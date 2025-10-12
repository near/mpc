use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use derive_more::{Deref, From};

const ED25519_PUBLIC_KEY_SIZE: usize = 32;
const SECP256K1_PUBLIC_KEY_SIZE: usize = 64;
const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const BLS12381G2_PUBLIC_KEY_SIZE: usize = 96;

#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum PublicKey {
    Secp256k1(Secp256k1PublicKey),
    Ed25519(Ed25519PublicKey),
    Bls12381(Bls12381G2PublicKey),
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deref,
    From,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_SIZE]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deref,
    From,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct Secp256k1PublicKey(pub [u8; SECP256K1_PUBLIC_KEY_SIZE]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deref,
    From,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct Bls12381G2PublicKey(pub [u8; BLS12381G2_PUBLIC_KEY_SIZE]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deref,
    From,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct Bls12381G1PublicKey(pub [u8; BLS12381G1_PUBLIC_KEY_SIZE]);

#[derive(Debug, thiserror::Error)]
pub enum ParsePublicKeyError {
    #[error("missing ':' separator")]
    MissingSeparator,
    #[error("wrong prefix")]
    WrongPrefix,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid bs58 encoding")]
    InvalidBs58Encoding,
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for Secp256k1PublicKey {
    fn is_referenceable() -> bool {
        true
    }

    fn schema_name() -> String {
        "Secp256k1PublicKey".to_string()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(generator)
    }
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for Bls12381G1PublicKey {
    fn is_referenceable() -> bool {
        true
    }

    fn schema_name() -> String {
        "Bls12381G1PublicKey".to_string()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(generator)
    }
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for Bls12381G2PublicKey {
    fn is_referenceable() -> bool {
        true
    }

    fn schema_name() -> String {
        "Bls12381G2PublicKey".to_string()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(generator)
    }
}

impl Ed25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Secp256k1PublicKey {
    pub fn as_bytes(&self) -> &[u8; SECP256K1_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Secp256k1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Bls12381G1PublicKey {
    pub fn as_bytes(&self) -> &[u8; BLS12381G1_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Bls12381G1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Bls12381G2PublicKey {
    pub fn as_bytes(&self) -> &[u8; BLS12381G2_PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Bls12381G2PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&PublicKey> for String {
    fn from(str_public_key: &PublicKey) -> Self {
        match str_public_key {
            PublicKey::Secp256k1(inner) => String::from(inner),
            PublicKey::Ed25519(inner) => String::from(inner),
            PublicKey::Bls12381(inner) => String::from(inner),
        }
    }
}

impl From<&Secp256k1PublicKey> for String {
    fn from(str_public_key: &Secp256k1PublicKey) -> Self {
        ["secp256k1:", &bs58::encode(str_public_key).into_string()].concat()
    }
}

impl From<&Ed25519PublicKey> for String {
    fn from(str_public_key: &Ed25519PublicKey) -> Self {
        ["ed25519:", &bs58::encode(str_public_key).into_string()].concat()
    }
}

impl From<&Bls12381G1PublicKey> for String {
    fn from(str_public_key: &Bls12381G1PublicKey) -> Self {
        ["bls12381g1:", &bs58::encode(str_public_key).into_string()].concat()
    }
}

impl From<&Bls12381G2PublicKey> for String {
    fn from(str_public_key: &Bls12381G2PublicKey) -> Self {
        ["bls12381g2:", &bs58::encode(str_public_key).into_string()].concat()
    }
}

impl std::str::FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(idx) = value.find(':') {
            let (prefix, _) = value.split_at(idx);
            match prefix {
                "ed25519" => Ok(Self::Ed25519(Ed25519PublicKey::from_str(value)?)),
                "secp256k1" => Ok(Self::Secp256k1(Secp256k1PublicKey::from_str(value)?)),
                "bls12381g2" => Ok(Self::Bls12381(Bls12381G2PublicKey::from_str(value)?)),
                _ => Err(ParsePublicKeyError::WrongPrefix),
            }
        } else {
            Err(ParsePublicKeyError::MissingSeparator)
        }
    }
}

impl std::str::FromStr for Secp256k1PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((prefix, key_data)) = value.split_once(':') else {
            return Err(ParsePublicKeyError::MissingSeparator);
        };

        if prefix != "secp256k1" {
            return Err(ParsePublicKeyError::WrongPrefix);
        }

        let data = bs58::decode(&key_data)
            .into_vec()
            .map_err(|_| ParsePublicKeyError::InvalidBs58Encoding)?;
        let bytes = data
            .try_into()
            .map_err(|_| ParsePublicKeyError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }
}

impl std::str::FromStr for Ed25519PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((prefix, key_data)) = value.split_once(':') else {
            return Err(ParsePublicKeyError::MissingSeparator);
        };

        if prefix != "ed25519" {
            return Err(ParsePublicKeyError::WrongPrefix);
        }

        let data = bs58::decode(&key_data)
            .into_vec()
            .map_err(|_| ParsePublicKeyError::InvalidBs58Encoding)?;
        let bytes = data
            .try_into()
            .map_err(|_| ParsePublicKeyError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }
}

impl std::str::FromStr for Bls12381G1PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((prefix, key_data)) = value.split_once(':') else {
            return Err(ParsePublicKeyError::MissingSeparator);
        };

        if prefix != "bls12381g1" {
            return Err(ParsePublicKeyError::WrongPrefix);
        }

        let data = bs58::decode(&key_data)
            .into_vec()
            .map_err(|_| ParsePublicKeyError::InvalidBs58Encoding)?;
        let bytes = data
            .try_into()
            .map_err(|_| ParsePublicKeyError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }
}

impl std::str::FromStr for Bls12381G2PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((prefix, key_data)) = value.split_once(':') else {
            return Err(ParsePublicKeyError::MissingSeparator);
        };

        if prefix != "bls12381g2" {
            return Err(ParsePublicKeyError::WrongPrefix);
        }

        let data = bs58::decode(&key_data)
            .into_vec()
            .map_err(|_| ParsePublicKeyError::InvalidBs58Encoding)?;
        let bytes = data
            .try_into()
            .map_err(|_| ParsePublicKeyError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        s.parse::<PublicKey>().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Secp256k1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> serde::Deserialize<'de> for Secp256k1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        s.parse::<Secp256k1PublicKey>()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        s.parse::<Ed25519PublicKey>()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Bls12381G1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> serde::Deserialize<'de> for Bls12381G1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        s.parse::<Bls12381G1PublicKey>()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Bls12381G2PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> serde::Deserialize<'de> for Bls12381G2PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        s.parse::<Bls12381G2PublicKey>()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_near_public_key_sizes() {
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
