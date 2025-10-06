use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

const ED25519_PUBLIC_KEY_SIZE: usize = 32;
const SECP256K1_PUBLIC_KEY_SIZE: usize = 64;

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
    // TODO(#1212): Add BLS types
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
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_SIZE]);

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
pub struct Secp256k1PublicKey(#[serde_as(as = "[_; 64]")] pub [u8; SECP256K1_PUBLIC_KEY_SIZE]);

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for Secp256k1PublicKey {
    fn schema_name() -> String {
        "Secp256k1PublicKey".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Array.into()),
            array: Some(Box::new(schemars::schema::ArrayValidation {
                min_items: Some(SECP256K1_PUBLIC_KEY_SIZE),
                max_items: Some(SECP256K1_PUBLIC_KEY_SIZE),
                items: Some(generator.subschema_for::<u8>().into()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
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
        let mut bytes = [0u8; SECP256K1_PUBLIC_KEY_SIZE];
        if let Some(idx) = value.find(':') {
            let (prefix, key_data) = value.split_at(idx);
            match prefix {
                "secp256k1" => {
                    let data = bs58::decode(&key_data[1..]).into_vec()?;
                    anyhow::ensure!(data.len() == SECP256K1_PUBLIC_KEY_SIZE);
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
        let mut bytes = [0u8; ED25519_PUBLIC_KEY_SIZE];
        if let Some(idx) = value.find(':') {
            let (prefix, key_data) = value.split_at(idx);
            match prefix {
                "ed25519" => {
                    let data = bs58::decode(&key_data[1..]).into_vec()?;
                    anyhow::ensure!(data.len() == ED25519_PUBLIC_KEY_SIZE);
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

#[cfg(test)]
mod tests {
    use crate::crypto::{ED25519_PUBLIC_KEY_SIZE, SECP256K1_PUBLIC_KEY_SIZE};

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
}
