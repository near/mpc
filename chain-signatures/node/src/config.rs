use std::collections::HashMap;
use std::str::FromStr;

use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The contract's config is a dynamic representation of all configurations possible.
pub type ContractConfig = HashMap<String, Value>;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub protocol: ProtocolConfig,
    pub local: LocalConfig,
}

impl Config {
    pub fn new(local: LocalConfig) -> Self {
        let mut protocol = ProtocolConfig::default();

        // We should also override are default initalized config if our overrides are present:
        if let Some(map) = local.over.entries.as_object() {
            if !map.is_empty() {
                let mut base = serde_json::to_value(protocol).unwrap();
                merge(&mut base, &local.over.entries);
                protocol = serde_json::from_value(base).unwrap();
            }
        }

        Self { protocol, local }
    }

    pub fn try_from_contract(mut contract: ContractConfig, original: &Config) -> Option<Self> {
        let mut protocol = contract.remove("protocol")?;
        merge(&mut protocol, &original.local.over.entries);
        let Ok(protocol) = serde_json::from_value(protocol) else {
            return None;
        };

        Some(Self {
            protocol,
            local: original.local.clone(),
        })
    }
}

/// All the local configurations on a node that are not accessible by anyone else
/// but the current node.
#[derive(Clone, Debug, Default)]
pub struct LocalConfig {
    pub network: NetworkConfig,
    pub over: OverrideConfig,
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_pk: hpke::PublicKey,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            sign_sk: near_crypto::SecretKey::from_seed(
                near_crypto::KeyType::ED25519,
                "test-entropy",
            ),
            cipher_pk: hpke::PublicKey::from_bytes(&[0; 32]),
        }
    }
}

/// The override config is the set of configurations we want to override from the
/// default configuration. This is a partial set of configurations, purely only
/// the values that the node wants to override.
///
/// The set of configs that can be overridden are only the non-[`LocalConfig`]
/// ones since we already control those.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OverrideConfig {
    entries: Value,
}

impl OverrideConfig {
    pub fn new(entries: Value) -> Self {
        Self { entries }
    }
}

impl FromStr for OverrideConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

pub fn merge(base: &mut Value, new: &Value) {
    match (base, new) {
        (base @ &mut Value::Object(_), Value::Object(new)) => {
            let base = base.as_object_mut().unwrap();
            for (key, new_value) in new {
                let base = base.entry(key).or_insert(Value::Null);
                merge(base, new_value);
            }
        }
        (base, new) => *base = new.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::merge;

    #[test]
    fn test_merge() {
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct B {
            c: i32,
            d: i32,
        }

        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct Base {
            a: i32,
            b: B,
        }

        let mut base = serde_json::json!( {
            "a": 1,
            "b": {
                "c": 2,
                "d": 3,
            },
        });

        let new = serde_json::json!({
            "b": {
                "c": 4,
                "e": 5,
            },
            "f": 6,
        });

        merge(&mut base, &new);
        let base: Base = serde_json::from_value(base).unwrap();
        dbg!(base);
    }
}
