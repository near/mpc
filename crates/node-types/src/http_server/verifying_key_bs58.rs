use anyhow::{self, Context};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ED25519_PREFIX: &str = "ed25519";

fn encode_key(key: &VerifyingKey) -> String {
    format!(
        "{ED25519_PREFIX}:{}",
        bs58::encode(key.as_bytes()).into_string()
    )
}

fn decode_key(s: &str) -> anyhow::Result<VerifyingKey> {
    let prefix = format!("{ED25519_PREFIX}:");
    let encoded = s
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("missing ED25519 prefix"))?;

    let bytes: [u8; 32] = bs58::decode(encoded)
        .into_vec()
        .context("base58 decode error")?
        .try_into()
        .map_err(|key_bytes: Vec<u8>| {
            anyhow::anyhow!("public key has unexpected length: {}", key_bytes.len())
        })?;

    VerifyingKey::from_bytes(&bytes).context("key is not valid")
}

pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode_key(key))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
where
    D: Deserializer<'de>,
{
    let base_58_encoded_key = String::deserialize(deserializer)?;
    decode_key(&base_58_encoded_key).map_err(serde::de::Error::custom)
}

pub mod vec {
    use super::*;
    pub fn serialize<S>(keys: &[VerifyingKey], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = keys.iter().map(encode_key).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<VerifyingKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base58_encoded_keys: Vec<String> = Vec::<String>::deserialize(deserializer)?;

        base58_encoded_keys
            .iter()
            .map(|base58_encoded_key| {
                decode_key(base58_encoded_key).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}
