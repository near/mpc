use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    From,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum PublicKey {
    Secp256k1(Secp256k1PublicKey),
    Ed25519(Ed25519PublicKey),
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
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[serde_as]
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
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Secp256k1PublicKey(#[serde_as(as = "[_; 64]")] pub [u8; 64]);

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for Secp256k1PublicKey {
    fn schema_name() -> String {
        "Secp256k1PublicKey".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Array.into()),
            array: Some(Box::new(schemars::schema::ArrayValidation {
                min_items: Some(64),
                max_items: Some(64),
                items: Some(generator.subschema_for::<u8>().into()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

impl Ed25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Secp256k1PublicKey {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for Secp256k1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// These conversions are only used in tests

#[cfg(feature = "test-utils")]
impl std::str::FromStr for PublicKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(idx) = value.find(':') {
            let (prefix, _) = value.split_at(idx);
            match prefix {
                "ed25519" => Ok(Self::Ed25519(Ed25519PublicKey::from_str(value)?)),
                "secp256k1" => Ok(Self::Secp256k1(Secp256k1PublicKey::from_str(value)?)),
                _ => anyhow::bail!("Unknown prefix"),
            }
        } else {
            anyhow::bail!("Separator not found")
        }
    }
}

#[cfg(feature = "test-utils")]
impl std::str::FromStr for Secp256k1PublicKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 64];
        if let Some(idx) = value.find(':') {
            let (prefix, key_data) = value.split_at(idx);
            match prefix {
                "secp256k1" => {
                    let data = bs58::decode(&key_data[1..]).into_vec()?;
                    anyhow::ensure!(data.len() == 64);
                    bytes.copy_from_slice(&data);
                    Ok(Self(bytes))
                }
                _ => anyhow::bail!("Unknown prefix"),
            }
        } else {
            anyhow::bail!("Separator not found")
        }
    }
}

#[cfg(feature = "test-utils")]
impl std::str::FromStr for Ed25519PublicKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];
        if let Some(idx) = value.find(':') {
            let (prefix, key_data) = value.split_at(idx);
            match prefix {
                "ed25519" => {
                    let data = bs58::decode(&key_data[1..]).into_vec()?;
                    anyhow::ensure!(data.len() == 32);
                    bytes.copy_from_slice(&data);
                    Ok(Self(bytes))
                }
                _ => anyhow::bail!("Unknown prefix"),
            }
        } else {
            anyhow::bail!("Separator not found")
        }
    }
}
