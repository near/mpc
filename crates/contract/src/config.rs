use crate::legacy_contract_state;
use near_sdk::near;

/// Default for `key_event_timeout_blocks`.
const DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS: u64 = 30;
/// Maximum time after which TEE MPC nodes must be upgraded to the latest version
const DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS: u64 = 7 * 24 * 60 * 60; // 7 Days
/// Amount of gas to deposit when creating an internal upgrade transaction promise.
/// Note this deposit must be less than 300, as the total gas usage including the
/// initial call itself to vote for the update can not exceed 300 Tgas.
const DEFAULT_CONTRACT_UPGRADE_DEPOSIT_TERA_GAS: u64 = 50;

/// Config for V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: u64,
    /// The grace period duration for expiry of old mpc image hashes once a new one is added.
    pub tee_upgrade_deadline_duration_seconds: u64,
    /// Amount of gas to deposit for contract and config updates.
    pub contract_upgrade_deposit_tera_gas: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
            tee_upgrade_deadline_duration_seconds: DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS,
            contract_upgrade_deposit_tera_gas: DEFAULT_CONTRACT_UPGRADE_DEPOSIT_TERA_GAS,
        }
    }
}

/// Config for initializing V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct InitConfig {
    pub key_event_timeout_blocks: Option<u64>,
    pub tee_upgrade_deadline_duration_seconds: Option<u64>,
    pub vote_update_minimum_gas_attached_tera_gas: Option<u64>,
}

impl From<Option<InitConfig>> for Config {
    fn from(init_config: Option<InitConfig>) -> Self {
        let Some(init_config) = init_config else {
            return Config::default();
        };

        let key_event_timeout_blocks = init_config
            .key_event_timeout_blocks
            .unwrap_or(DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS);

        let tee_upgrade_deadline_duration_seconds = init_config
            .tee_upgrade_deadline_duration_seconds
            .unwrap_or(DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS);

        let contract_upgrade_deposit_tera_gas = init_config
            .vote_update_minimum_gas_attached_tera_gas
            .unwrap_or(DEFAULT_CONTRACT_UPGRADE_DEPOSIT_TERA_GAS);

        Config {
            key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds,
            contract_upgrade_deposit_tera_gas,
        }
    }
}

impl From<&legacy_contract_state::ConfigV1> for Config {
    fn from(_config: &legacy_contract_state::ConfigV1) -> Self {
        Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            key_event_timeout_blocks: 2000,
            tee_upgrade_deadline_duration_seconds: 3333,
            contract_upgrade_deposit_tera_gas: 120,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_init_config_serialization() {
        let init_config = InitConfig {
            key_event_timeout_blocks: None,
            tee_upgrade_deadline_duration_seconds: None,
            vote_update_minimum_gas_attached_tera_gas: None,
        };
        let json = serde_json::to_string(&init_config).unwrap();
        let deserialized: InitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(init_config, deserialized);
    }

    #[test]
    fn test_init_config_to_config_conversion() {
        let init_config = InitConfig {
            key_event_timeout_blocks: None,
            tee_upgrade_deadline_duration_seconds: None,
            vote_update_minimum_gas_attached_tera_gas: None,
        };
        let converted_config: Config = Some(init_config).into();
        let default_config = Config::default();
        assert_eq!(converted_config, default_config);
    }

    #[test]
    fn test_init_config_is_none_to_config_conversion() {
        let init_config: Option<InitConfig> = None;
        let converted_config: Config = init_config.into();
        let default_config = Config::default();
        assert_eq!(converted_config, default_config);
    }
}
