use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const BLS12381G2_PUBLIC_KEY_SIZE: usize = 96;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deref, From)]
pub struct Bls12381G2PublicKey(pub [u8; BLS12381G2_PUBLIC_KEY_SIZE]);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deref, From)]
pub struct Bls12381G1PublicKey(pub [u8; BLS12381G1_PUBLIC_KEY_SIZE]);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, derive_more::Constructor)]
pub struct CKDResponse {
    pub big_y: Bls12381G1PublicKey,
    pub big_c: Bls12381G1PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, derive_more::Constructor)]
pub struct CKDArgs {
    pub app_public_key: Bls12381G1PublicKey,
    pub domain_id: DomainId,
}

#[derive(Clone, Debug, Serialize, Deserialize, derive_more::Constructor)]
pub struct CKDRequestArgs {
    pub request: CKDArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, derive_more::Constructor)]
pub struct DomainId(pub u64);

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

impl FromStr for DomainId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.parse::<u64>()?;
        Ok(DomainId::new(v))
    }
}
