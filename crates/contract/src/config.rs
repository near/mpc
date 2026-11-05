use near_mpc_contract_interface::types::{Config, InitConfig};

// --- Timeouts & Deadlines ---
/// Default for `key_event_timeout_blocks`.
pub(crate) const DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS: u64 = 150;
/// Maximum time after which TEE MPC nodes must be upgraded to the latest version
const DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS: u64 = 7 * 24 * 60 * 60; // 7 Days

// --- Gas Defaults (in TeraGas) ---
/// Prepaid gas for applying contract and config updates.
const DEFAULT_APPLY_CONTRACT_UPDATE_TERA_GAS: u64 = 50;
/// Gas required for a sign request
const DEFAULT_SIGN_CALL_GAS_ATTACHMENT_REQUIREMENT_TERA_GAS: u64 = 15;
/// Gas required for a CKD request
const DEFAULT_CKD_CALL_GAS_ATTACHMENT_REQUIREMENT_TERA_GAS: u64 = 15;
/// Prepaid gas for a `return_signature_and_clean_state_on_success` call
const DEFAULT_RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_TERA_GAS: u64 = 7;
/// Prepaid gas for a `return_ck_and_clean_state_on_success` call
const DEFAULT_RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_CALL_TERA_GAS: u64 = 7;
/// Prepaid gas for a `fail_on_timeout` call
const DEFAULT_FAIL_ON_TIMEOUT_TERA_GAS: u64 = 2;
/// Prepaid gas for a `fail_attestation_submission` call
const DEFAULT_FAIL_ATTESTATION_SUBMISSION_TERA_GAS: u64 = 2;
/// Prepaid gas for a `clean_tee_status` call
const DEFAULT_CLEAN_TEE_STATUS_TERA_GAS: u64 = 10;
/// Prepaid gas for the reshare-time `clean_invalid_attestations` promise.
const DEFAULT_CLEAN_INVALID_ATTESTATIONS_TERA_GAS: u64 = 15;
/// Prepaid gas for a `cleanup_orphaned_node_migrations` call
/// TODO(#1164): benchmark
pub(crate) const DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS: u64 = 7;
/// Prepaid gas for a `remove_non_participant_contract_update_votes` call
const DEFAULT_REMOVE_NON_PARTICIPANT_UPDATE_VOTES_TERA_GAS: u64 = 5;
/// Prepaid gas for a `clean_foreign_chain_data` call
pub(crate) const DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS: u64 = 8;
/// Prepaid gas for a `remove_non_participant_tee_verifier_votes` call
const DEFAULT_REMOVE_NON_PARTICIPANT_TEE_VERIFIER_VOTES_TERA_GAS: u64 = 5;
/// Gas attached to the cross-contract `verify_quote_with_collateral_dates` call on the TEE verifier.
const DEFAULT_VERIFIER_TERA_GAS: u64 = 200;
/// Prepaid gas for the `resolve_verification` callback. Carries the bulk of the
/// post-DCAP work (allowlist match, RTMR3 replay, app-compose validation, store).
const DEFAULT_RESOLVE_VERIFICATION_TERA_GAS: u64 = 60;
/// Default TTL after which a launcher image hash unused by any participant is evicted.
pub(crate) const DEFAULT_LAUNCHER_HASH_UNUSED_TTL_SECONDS: u64 = 14 * 24 * 60 * 60; // 14 days

/// One attestation-storage grant, in milliNEAR.
pub(crate) const DEFAULT_ATTESTATION_STORAGE_FEE_MILLINEAR: u64 = 20;

/// Builds the contract config from `init`, filling every unset field with its default.
pub(crate) fn config_from_init(init: InitConfig) -> Config {
    Config {
        key_event_timeout_blocks: init
            .key_event_timeout_blocks
            .unwrap_or(DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS),
        tee_upgrade_deadline_duration_seconds: init
            .tee_upgrade_deadline_duration_seconds
            .unwrap_or(DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS),
        apply_contract_update_tera_gas: init
            .apply_contract_update_tera_gas
            .unwrap_or(DEFAULT_APPLY_CONTRACT_UPDATE_TERA_GAS),
        sign_call_gas_attachment_requirement_tera_gas: init
            .sign_call_gas_attachment_requirement_tera_gas
            .unwrap_or(DEFAULT_SIGN_CALL_GAS_ATTACHMENT_REQUIREMENT_TERA_GAS),
        ckd_call_gas_attachment_requirement_tera_gas: init
            .ckd_call_gas_attachment_requirement_tera_gas
            .unwrap_or(DEFAULT_CKD_CALL_GAS_ATTACHMENT_REQUIREMENT_TERA_GAS),
        return_signature_and_clean_state_on_success_call_tera_gas: init
            .return_signature_and_clean_state_on_success_call_tera_gas
            .unwrap_or(DEFAULT_RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_TERA_GAS),
        return_ck_and_clean_state_on_success_call_tera_gas: init
            .return_ck_and_clean_state_on_success_call_tera_gas
            .unwrap_or(DEFAULT_RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_CALL_TERA_GAS),
        fail_on_timeout_tera_gas: init
            .fail_on_timeout_tera_gas
            .unwrap_or(DEFAULT_FAIL_ON_TIMEOUT_TERA_GAS),
        fail_attestation_submission_tera_gas: init
            .fail_attestation_submission_tera_gas
            .unwrap_or(DEFAULT_FAIL_ATTESTATION_SUBMISSION_TERA_GAS),
        clean_tee_status_tera_gas: init
            .clean_tee_status_tera_gas
            .unwrap_or(DEFAULT_CLEAN_TEE_STATUS_TERA_GAS),
        clean_invalid_attestations_tera_gas: init
            .clean_invalid_attestations_tera_gas
            .unwrap_or(DEFAULT_CLEAN_INVALID_ATTESTATIONS_TERA_GAS),
        cleanup_orphaned_node_migrations_tera_gas: init
            .cleanup_orphaned_node_migrations_tera_gas
            .unwrap_or(DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS),
        remove_non_participant_update_votes_tera_gas: init
            .remove_non_participant_update_votes_tera_gas
            .unwrap_or(DEFAULT_REMOVE_NON_PARTICIPANT_UPDATE_VOTES_TERA_GAS),
        clean_foreign_chain_data_tera_gas: init
            .clean_foreign_chain_data_tera_gas
            .unwrap_or(DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS),
        remove_non_participant_tee_verifier_votes_tera_gas: init
            .remove_non_participant_tee_verifier_votes_tera_gas
            .unwrap_or(DEFAULT_REMOVE_NON_PARTICIPANT_TEE_VERIFIER_VOTES_TERA_GAS),
        verifier_tera_gas: init.verifier_tera_gas.unwrap_or(DEFAULT_VERIFIER_TERA_GAS),
        resolve_verification_tera_gas: init
            .resolve_verification_tera_gas
            .unwrap_or(DEFAULT_RESOLVE_VERIFICATION_TERA_GAS),
        launcher_hash_unused_ttl_seconds: init
            .launcher_hash_unused_ttl_seconds
            .unwrap_or(DEFAULT_LAUNCHER_HASH_UNUSED_TTL_SECONDS),
        attestation_storage_fee_millinear: init
            .attestation_storage_fee_millinear
            .unwrap_or(DEFAULT_ATTESTATION_STORAGE_FEE_MILLINEAR),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn config_from_init__should_fill_unset_fields_with_defaults() {
        // Given
        let init = InitConfig::default();

        // When
        let config = config_from_init(init);

        // Then
        assert_eq!(
            config,
            Config {
                key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
                tee_upgrade_deadline_duration_seconds:
                    DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS,
                apply_contract_update_tera_gas: DEFAULT_APPLY_CONTRACT_UPDATE_TERA_GAS,
                sign_call_gas_attachment_requirement_tera_gas:
                    DEFAULT_SIGN_CALL_GAS_ATTACHMENT_REQUIREMENT_TERA_GAS,
                ckd_call_gas_attachment_requirement_tera_gas:
                    DEFAULT_CKD_CALL_GAS_ATTACHMENT_REQUIREMENT_TERA_GAS,
                return_signature_and_clean_state_on_success_call_tera_gas:
                    DEFAULT_RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_TERA_GAS,
                return_ck_and_clean_state_on_success_call_tera_gas:
                    DEFAULT_RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_CALL_TERA_GAS,
                fail_on_timeout_tera_gas: DEFAULT_FAIL_ON_TIMEOUT_TERA_GAS,
                fail_attestation_submission_tera_gas: DEFAULT_FAIL_ATTESTATION_SUBMISSION_TERA_GAS,
                clean_tee_status_tera_gas: DEFAULT_CLEAN_TEE_STATUS_TERA_GAS,
                clean_invalid_attestations_tera_gas: DEFAULT_CLEAN_INVALID_ATTESTATIONS_TERA_GAS,
                cleanup_orphaned_node_migrations_tera_gas:
                    DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS,
                remove_non_participant_update_votes_tera_gas:
                    DEFAULT_REMOVE_NON_PARTICIPANT_UPDATE_VOTES_TERA_GAS,
                clean_foreign_chain_data_tera_gas: DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS,
                remove_non_participant_tee_verifier_votes_tera_gas:
                    DEFAULT_REMOVE_NON_PARTICIPANT_TEE_VERIFIER_VOTES_TERA_GAS,
                verifier_tera_gas: DEFAULT_VERIFIER_TERA_GAS,
                resolve_verification_tera_gas: DEFAULT_RESOLVE_VERIFICATION_TERA_GAS,
                launcher_hash_unused_ttl_seconds: DEFAULT_LAUNCHER_HASH_UNUSED_TTL_SECONDS,
                attestation_storage_fee_millinear: DEFAULT_ATTESTATION_STORAGE_FEE_MILLINEAR,
            }
        );
    }

    #[test]
    fn config_from_init__should_keep_provided_fields() {
        // Given
        let init = InitConfig {
            key_event_timeout_blocks: Some(1),
            tee_upgrade_deadline_duration_seconds: Some(2),
            apply_contract_update_tera_gas: Some(3),
            sign_call_gas_attachment_requirement_tera_gas: Some(4),
            ckd_call_gas_attachment_requirement_tera_gas: Some(5),
            return_signature_and_clean_state_on_success_call_tera_gas: Some(6),
            return_ck_and_clean_state_on_success_call_tera_gas: Some(7),
            fail_on_timeout_tera_gas: Some(8),
            fail_attestation_submission_tera_gas: Some(9),
            clean_tee_status_tera_gas: Some(10),
            clean_invalid_attestations_tera_gas: Some(11),
            cleanup_orphaned_node_migrations_tera_gas: Some(12),
            remove_non_participant_update_votes_tera_gas: Some(13),
            clean_foreign_chain_data_tera_gas: Some(14),
            remove_non_participant_tee_verifier_votes_tera_gas: Some(15),
            verifier_tera_gas: Some(16),
            resolve_verification_tera_gas: Some(17),
            launcher_hash_unused_ttl_seconds: Some(18),
            attestation_storage_fee_millinear: Some(19),
        };

        // When
        let config = config_from_init(init);

        // Then
        assert_eq!(
            config,
            Config {
                key_event_timeout_blocks: 1,
                tee_upgrade_deadline_duration_seconds: 2,
                apply_contract_update_tera_gas: 3,
                sign_call_gas_attachment_requirement_tera_gas: 4,
                ckd_call_gas_attachment_requirement_tera_gas: 5,
                return_signature_and_clean_state_on_success_call_tera_gas: 6,
                return_ck_and_clean_state_on_success_call_tera_gas: 7,
                fail_on_timeout_tera_gas: 8,
                fail_attestation_submission_tera_gas: 9,
                clean_tee_status_tera_gas: 10,
                clean_invalid_attestations_tera_gas: 11,
                cleanup_orphaned_node_migrations_tera_gas: 12,
                remove_non_participant_update_votes_tera_gas: 13,
                clean_foreign_chain_data_tera_gas: 14,
                remove_non_participant_tee_verifier_votes_tera_gas: 15,
                verifier_tera_gas: 16,
                resolve_verification_tera_gas: 17,
                launcher_hash_unused_ttl_seconds: 18,
                attestation_storage_fee_millinear: 19,
            }
        );
    }
}
