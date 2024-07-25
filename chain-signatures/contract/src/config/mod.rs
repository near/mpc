mod impls;

pub use impls::{min_to_ms, secs_to_ms};

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicValue(serde_json::Value);

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
