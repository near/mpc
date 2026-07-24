use near_sdk::near;

// --- Timeouts & Deadlines ---
/// Default for `key_event_timeout_blocks`.
const DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS: u64 = 30;
/// Maximum time after which TEE MPC nodes must be upgraded to the latest version
const DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS: u64 = 7 * 24 * 60 * 60; // 7 Days

// --- Gas Defaults (in TeraGas) ---
/// Amount of gas to deposit when creating an internal upgrade transaction promise.
/// Note this deposit must be less than 300, as the total gas usage including the
/// initial call itself to vote for the update can not exceed 300 Tgas.
const DEFAULT_CONTRACT_UPGRADE_DEPOSIT_TERA_GAS: u64 = 50;
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
const DEFAULT_CLEAN_INVALID_ATTESTATIONS_TERA_GAS: u64 = 10;
/// Prepaid gas for a `cleanup_orphaned_node_migrations` call
/// TODO(#1164): benchmark
const DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS: u64 = 4;
/// Prepaid gas for a `remove_non_participant_update_votes` call
const DEFAULT_REMOVE_NON_PARTICIPANT_UPDATE_VOTES_TERA_GAS: u64 = 5;
/// Prepaid gas for a `clean_foreign_chain_data` call
const DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS: u64 = 5;
/// Prepaid gas for a `remove_non_participant_tee_verifier_votes` call
const DEFAULT_REMOVE_NON_PARTICIPANT_TEE_VERIFIER_VOTES_TERA_GAS: u64 = 5;
/// Gas attached to the cross-contract `verify_quote` call on the TEE verifier.
const DEFAULT_VERIFIER_TERA_GAS: u64 = 200;
/// Prepaid gas for the `resolve_verification` callback. Carries the bulk of the
/// post-DCAP work (allowlist match, RTMR3 replay, app-compose validation, store).
const DEFAULT_RESOLVE_VERIFICATION_TERA_GAS: u64 = 60;
/// Default TTL after which a launcher image hash unused by any participant is evicted.
const DEFAULT_LAUNCHER_HASH_UNUSED_TTL_SECONDS: u64 = 14 * 24 * 60 * 60; // 14 days
/// Prepaid gas for a `clean_expired_launcher_hashes` call.
const DEFAULT_CLEAN_EXPIRED_LAUNCHER_HASHES_TERA_GAS: u64 = 5;

/// Config for V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub(crate) key_event_timeout_blocks: u64,
    /// The grace period duration for expiry of old mpc image hashes once a new one is added.
    pub(crate) tee_upgrade_deadline_duration_seconds: u64,
    /// Amount of gas to deposit for contract and config updates.
    pub(crate) contract_upgrade_deposit_tera_gas: u64,
    /// Gas required for a sign request.
    pub(crate) sign_call_gas_attachment_requirement_tera_gas: u64,
    /// Gas required for a CKD request.
    pub(crate) ckd_call_gas_attachment_requirement_tera_gas: u64,
    /// Prepaid gas for a `return_signature_and_clean_state_on_success` call.
    pub(crate) return_signature_and_clean_state_on_success_call_tera_gas: u64,
    /// Prepaid gas for a `return_ck_and_clean_state_on_success` call.
    pub(crate) return_ck_and_clean_state_on_success_call_tera_gas: u64,
    /// Prepaid gas for a `fail_on_timeout` call.
    pub(crate) fail_on_timeout_tera_gas: u64,
    /// Prepaid gas for a `fail_attestation_submission` call.
    pub(crate) fail_attestation_submission_tera_gas: u64,
    /// Prepaid gas for a `clean_tee_status` call.
    pub(crate) clean_tee_status_tera_gas: u64,
    /// Prepaid gas for the reshare-time `clean_invalid_attestations` promise.
    pub(crate) clean_invalid_attestations_tera_gas: u64,
    /// Prepaid gas for a `cleanup_orphaned_node_migrations` call.
    pub(crate) cleanup_orphaned_node_migrations_tera_gas: u64,
    /// Prepaid gas for a `remove_non_participant_update_votes` call.
    pub(crate) remove_non_participant_update_votes_tera_gas: u64,
    /// Prepaid gas for a `clean_foreign_chain_data` call.
    pub(crate) clean_foreign_chain_data_tera_gas: u64,
    /// Prepaid gas for a `remove_non_participant_tee_verifier_votes` call.
    pub(crate) remove_non_participant_tee_verifier_votes_tera_gas: u64,
    /// Gas attached to the cross-contract `verify_quote` call on the verifier.
    pub(crate) verifier_tera_gas: u64,
    /// Prepaid gas for the `resolve_verification` callback.
    pub(crate) resolve_verification_tera_gas: u64,
    /// TTL after which a launcher image hash unused by any participant is evicted.
    pub(crate) launcher_hash_unused_ttl_seconds: u64,
    /// Prepaid gas for a `clean_expired_launcher_hashes` call.
    pub(crate) clean_expired_launcher_hashes_tera_gas: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
            tee_upgrade_deadline_duration_seconds: DEFAULT_TEE_UPGRADE_DEADLINE_DURATION_SECONDS,
            contract_upgrade_deposit_tera_gas: DEFAULT_CONTRACT_UPGRADE_DEPOSIT_TERA_GAS,
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
            clean_expired_launcher_hashes_tera_gas: DEFAULT_CLEAN_EXPIRED_LAUNCHER_HASHES_TERA_GAS,
        }
    }
}

impl Config {
    /// Invariant: a launcher hash backing a still-valid attestation must never expire,
    /// so its unused-TTL must be at least the attestation validity window.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.launcher_hash_unused_ttl_seconds
            < mpc_attestation::attestation::DEFAULT_EXPIRATION_DURATION_SECONDS
        {
            return Err(
                "launcher_hash_unused_ttl_seconds must be >= DEFAULT_EXPIRATION_DURATION_SECONDS",
            );
        }
        Ok(())
    }
}
