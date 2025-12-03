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
/// Prepaid gas for a `clean_tee_status` call
const DEFAULT_CLEAN_TEE_STATUS_TERA_GAS: u64 = 10;
/// Prepaid gas for a `cleanup_orphaned_node_migrations` call
/// todo: benchmark [#1164](https://github.com/near/mpc/issues/1164)
const DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS: u64 = 3;
/// Prepaid gas for a `remove_non_participant_update_votes` call
const DEFAULT_REMOVE_NON_PARTICIPANT_UPDATE_VOTES_TERA_GAS: u64 = 5;

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
    /// Prepaid gas for a `clean_tee_status` call.
    pub(crate) clean_tee_status_tera_gas: u64,
    /// Prepaid gas for a `cleanup_orphaned_node_migrations` call.
    pub(crate) cleanup_orphaned_node_migrations_tera_gas: u64,
    /// Prepaid gas for a `remove_non_participant_update_votes` call.
    pub(crate) remove_non_participant_update_votes_tera_gas: u64,
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
            clean_tee_status_tera_gas: DEFAULT_CLEAN_TEE_STATUS_TERA_GAS,
            cleanup_orphaned_node_migrations_tera_gas:
                DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS,
            remove_non_participant_update_votes_tera_gas:
                DEFAULT_REMOVE_NON_PARTICIPANT_UPDATE_VOTES_TERA_GAS,
        }
    }
}
