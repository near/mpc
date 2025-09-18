use crate::legacy_contract_state;
use near_sdk::near;

/// Default for `key_event_timeout_blocks`.
const DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS: u64 = 30;
/// Maximum time after which TEE MPC nodes must be upgraded to the latest version
const DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS: u64 = 7 * 24 * 60 * 100; // ~7 days @ block time of 600 ms, e.g. 100 blocks every 60 seconds

/// Config for V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: u64,
    /// How long an attestation should be considered valid.
    /// For how many blocks should old
    pub tee_upgrade_deadline_duration_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
            tee_upgrade_deadline_duration_blocks: DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS,
        }
    }
}

/// Config for initializing V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitConfig {
    pub key_event_timeout_blocks: Option<u64>,
    pub tee_upgrade_deadline_duration_blocks: Option<u64>,
}

impl From<Option<InitConfig>> for Config {
    fn from(init_config: Option<InitConfig>) -> Self {
        let Some(init_config) = init_config else {
            return Config::default();
        };

        let key_event_timeout_blocks = init_config
            .key_event_timeout_blocks
            .unwrap_or(DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS);

        let tee_upgrade_deadline_duration_blocks = init_config
            .tee_upgrade_deadline_duration_blocks
            .unwrap_or(DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);

        Config {
            key_event_timeout_blocks,
            tee_upgrade_deadline_duration_blocks,
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
            tee_upgrade_deadline_duration_blocks: 3333,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_init_config_serialization() {
        let init_config = InitConfig {
            key_event_timeout_blocks: None,
            tee_upgrade_deadline_duration_blocks: None,
        };
        let json = serde_json::to_string(&init_config).unwrap();
        let deserialized: InitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(init_config, deserialized);
    }

    #[test]
    fn test_init_config_to_config_conversion() {
        let init_config = InitConfig {
            key_event_timeout_blocks: None,
            tee_upgrade_deadline_duration_blocks: None,
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
