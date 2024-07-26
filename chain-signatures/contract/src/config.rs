use std::collections::HashMap;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[derive(
    Clone, Default, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq,
)]
pub struct Config {
    #[serde(flatten)]
    pub entries: HashMap<String, DynamicValue>,
}

impl Config {
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        let value = self.entries.get(key)?;
        Some(&value.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicValue(serde_json::Value);

impl From<serde_json::Value> for DynamicValue {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}

impl BorshSerialize for DynamicValue {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let buf = serde_json::to_vec(&self.0)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        BorshSerialize::serialize(&buf, writer)
    }
}

impl BorshDeserialize for DynamicValue {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let buf: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let value = serde_json::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self(value))
    }
}

pub const fn secs_to_ms(secs: u64) -> u64 {
    secs * 1000
}

pub const fn min_to_ms(min: u64) -> u64 {
    min * 60 * 1000
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_load_config() {
        let config_str: serde_json::Value = serde_json::from_str(
            r#"{
                "triple_timeout": 20000,
                "presignature_timeout": 30000,
                "signature_timeout": 30000,
                "string": "value",
                "integer": 1000
            }"#,
        )
        .unwrap();

        let config_macro = serde_json::json!({
            "triple_timeout": 20000,
            "presignature_timeout": 30000,
            "signature_timeout": 30000,
            "string": "value",
            "integer": 1000,
        });

        assert_eq!(config_str, config_macro);

        let config: Config = serde_json::from_value(config_macro).unwrap();
        assert_eq!(config.get("string").unwrap(), &serde_json::json!("value"),);
        assert_eq!(config.get("integer").unwrap(), &serde_json::json!(1000),);
    }
}
