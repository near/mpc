/// The initial configuration parameters for when initializing the contract.
/// All fields are optional, as the contract can fill in defaults for any
/// missing fields.
#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct InitConfig {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: Option<u64>,
    /// The grace period duration for expiry of old mpc image hashes once a new one is added.
    pub tee_upgrade_deadline_duration_seconds: Option<u64>,
    /// Amount of gas to deposit for contract and config updates.
    pub contract_upgrade_deposit_tera_gas: Option<u64>,
    /// Gas required for a sign request.
    pub sign_call_gas_attachment_requirement_tera_gas: Option<u64>,
    /// Prepaid gas for a `return_signature_and_clean_state_on_success` call.
    pub ckd_call_gas_attachment_requirement_tera_gas: Option<u64>,
    /// Prepaid gas for a `return_signature_and_clean_state_on_success` call.
    pub return_signature_and_clean_state_on_success_call_tera_gas: Option<u64>,
    /// Prepaid gas for a `return_ck_and_clean_state_on_success` call.
    pub return_ck_and_clean_state_on_success_call_tera_gas: Option<u64>,
    /// Prepaid gas for a `fail_on_timeout` call.
    pub fail_on_timeout_tera_gas: Option<u64>,
    /// Prepaid gas for a `clean_tee_status` call.
    pub clean_tee_status_tera_gas: Option<u64>,
    /// Prepaid gas for a `cleanup_orphaned_node_migrations` call.
    pub cleanup_orphaned_node_migrations_tera_gas: Option<u64>,
    /// Prepaid gas for a `remove_non_participant_update_votes` call.
    pub remove_non_participant_update_votes_tera_gas: Option<u64>,
}

/// Configuration parameters of the contract.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: u64,
    /// The grace period duration for expiry of old mpc image hashes once a new one is added.
    pub tee_upgrade_deadline_duration_seconds: u64,
    /// Amount of gas to deposit for contract and config updates.
    pub contract_upgrade_deposit_tera_gas: u64,
    /// Gas required for a sign request.
    pub sign_call_gas_attachment_requirement_tera_gas: u64,
    /// Prepaid gas for a `return_signature_and_clean_state_on_success` call.
    pub ckd_call_gas_attachment_requirement_tera_gas: u64,
    /// Prepaid gas for a `return_signature_and_clean_state_on_success` call.
    pub return_signature_and_clean_state_on_success_call_tera_gas: u64,
    /// Prepaid gas for a `return_ck_and_clean_state_on_success` call.
    pub return_ck_and_clean_state_on_success_call_tera_gas: u64,
    /// Prepaid gas for a `fail_on_timeout` call.
    pub fail_on_timeout_tera_gas: u64,
    /// Prepaid gas for a `clean_tee_status` call.
    pub clean_tee_status_tera_gas: u64,
    /// Prepaid gas for a `cleanup_orphaned_node_migrations` call.
    pub cleanup_orphaned_node_migrations_tera_gas: u64,
    /// Prepaid gas for a `remove_non_participant_update_votes` call.
    pub remove_non_participant_update_votes_tera_gas: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_config_round_trip_serialization() {
        let original_config = InitConfig {
            key_event_timeout_blocks: Some(2000),
            tee_upgrade_deadline_duration_seconds: Some(3333),
            contract_upgrade_deposit_tera_gas: Some(120),
            sign_call_gas_attachment_requirement_tera_gas: Some(15),
            ckd_call_gas_attachment_requirement_tera_gas: Some(15),
            return_signature_and_clean_state_on_success_call_tera_gas: Some(7),
            return_ck_and_clean_state_on_success_call_tera_gas: Some(7),
            fail_on_timeout_tera_gas: Some(2),
            clean_tee_status_tera_gas: Some(10),
            cleanup_orphaned_node_migrations_tera_gas: Some(3),
            remove_non_participant_update_votes_tera_gas: Some(5),
        };
        let json = serde_json::to_string(&original_config).unwrap();
        let serialized_and_deserialized_config: InitConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(original_config, serialized_and_deserialized_config);
    }

    #[test]
    fn test_config_defaults_from_empty_json() {
        // Test that an empty JSON object results in a default config.
        let json = "{}";
        let deserialized: InitConfig = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized, InitConfig::default());
    }

    #[test]
    fn test_config_partial_update() {
        // Test that providing only one field updates that field and defaults the rest
        // Note: The key name must match the struct field name.
        let json = r#"{"key_event_timeout_blocks": 9999}"#;

        let deserialized: InitConfig = serde_json::from_str(json).unwrap();

        let expected = InitConfig {
            key_event_timeout_blocks: Some(9999),
            ..Default::default()
        };

        assert_eq!(deserialized, expected);
        assert_eq!(deserialized.key_event_timeout_blocks, Some(9999));
    }

    #[test]
    fn default_implementation_sets_all_values_to_none() {
        let default_config = InitConfig::default();
        let config_with_all_values_as_none = InitConfig {
            key_event_timeout_blocks: None,
            tee_upgrade_deadline_duration_seconds: None,
            contract_upgrade_deposit_tera_gas: None,
            sign_call_gas_attachment_requirement_tera_gas: None,
            ckd_call_gas_attachment_requirement_tera_gas: None,
            return_signature_and_clean_state_on_success_call_tera_gas: None,
            return_ck_and_clean_state_on_success_call_tera_gas: None,
            fail_on_timeout_tera_gas: None,
            clean_tee_status_tera_gas: None,
            cleanup_orphaned_node_migrations_tera_gas: None,
            remove_non_participant_update_votes_tera_gas: None,
        };

        assert_eq!(default_config, config_with_all_values_as_none);
    }
}
