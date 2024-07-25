use std::collections::HashMap;

use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke;

/// The contract's config is a dynamic representation of all configurations possible.
pub type ContractConfig = HashMap<String, serde_json::Value>;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub protocol: ProtocolConfig,
    pub local: LocalConfig,
}

impl Config {
    pub fn try_from_contract(mut contract: ContractConfig, original: &Config) -> Option<Self> {
        let Ok(protocol) = serde_json::from_value(contract.remove("protocol")?) else {
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
