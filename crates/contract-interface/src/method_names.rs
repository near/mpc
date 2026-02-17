//! Contract method name constants for the MPC signer contract.
//!
//! Provides a single source of truth for method names used across the node,
//! contract, tests, and by external callers.

// User request methods
pub const SIGN: &str = "sign";
pub const REQUEST_APP_PRIVATE_KEY: &str = "request_app_private_key";
pub const VERIFY_FOREIGN_TRANSACTION: &str = "verify_foreign_transaction";

// Node response methods
pub const RESPOND: &str = "respond";
pub const RESPOND_CKD: &str = "respond_ckd";
pub const RESPOND_VERIFY_FOREIGN_TX: &str = "respond_verify_foreign_tx";

// Vote methods
pub const VOTE_PK: &str = "vote_pk";
pub const VOTE_RESHARED: &str = "vote_reshared";
pub const VOTE_NEW_PARAMETERS: &str = "vote_new_parameters";
pub const VOTE_ADD_DOMAINS: &str = "vote_add_domains";
pub const VOTE_FOREIGN_CHAIN_POLICY: &str = "vote_foreign_chain_policy";
pub const VOTE_CODE_HASH: &str = "vote_code_hash";
pub const VOTE_CANCEL_KEYGEN: &str = "vote_cancel_keygen";
pub const VOTE_CANCEL_RESHARING: &str = "vote_cancel_resharing";
pub const VOTE_ABORT_KEY_EVENT_INSTANCE: &str = "vote_abort_key_event_instance";
pub const VOTE_UPDATE: &str = "vote_update";
pub const REMOVE_UPDATE_VOTE: &str = "remove_update_vote";
pub const REMOVE_NON_PARTICIPANT_UPDATE_VOTES: &str = "remove_non_participant_update_votes";

// Protocol management
pub const INIT: &str = "init";
pub const INIT_RUNNING: &str = "init_running";
pub const MIGRATE: &str = "migrate";
pub const START_KEYGEN_INSTANCE: &str = "start_keygen_instance";
pub const START_RESHARE_INSTANCE: &str = "start_reshare_instance";
pub const PROPOSE_UPDATE: &str = "propose_update";
pub const UPDATE_CONFIG: &str = "update_config";
pub const FAIL_ON_TIMEOUT: &str = "fail_on_timeout";

// TEE / Participant
pub const SUBMIT_PARTICIPANT_INFO: &str = "submit_participant_info";
pub const VERIFY_TEE: &str = "verify_tee";
pub const CONCLUDE_NODE_MIGRATION: &str = "conclude_node_migration";
pub const START_NODE_MIGRATION: &str = "start_node_migration";
pub const REGISTER_BACKUP_SERVICE: &str = "register_backup_service";
pub const CLEANUP_ORPHANED_NODE_MIGRATIONS: &str = "cleanup_orphaned_node_migrations";
pub const CLEAN_TEE_STATUS: &str = "clean_tee_status";

// Callbacks (used in promise_yield_create and indexed by the node)
pub const RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS: &str =
    "return_signature_and_clean_state_on_success";
pub const RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS: &str = "return_ck_and_clean_state_on_success";
pub const RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS: &str =
    "return_verify_foreign_tx_and_clean_state_on_success";

// View methods
pub const STATE: &str = "state";
pub const CONFIG: &str = "config";
pub const PUBLIC_KEY: &str = "public_key";
pub const DERIVED_PUBLIC_KEY: &str = "derived_public_key";
pub const VERSION: &str = "version";
pub const LATEST_KEY_VERSION: &str = "latest_key_version";
pub const PROPOSED_UPDATES: &str = "proposed_updates";
pub const GET_PENDING_REQUEST: &str = "get_pending_request";
pub const GET_PENDING_CKD_REQUEST: &str = "get_pending_ckd_request";
pub const GET_PENDING_VERIFY_FOREIGN_TX_REQUEST: &str = "get_pending_verify_foreign_tx_request";
pub const GET_TEE_ACCOUNTS: &str = "get_tee_accounts";
pub const GET_ATTESTATION: &str = "get_attestation";
pub const GET_FOREIGN_CHAIN_POLICY: &str = "get_foreign_chain_policy";
pub const GET_FOREIGN_CHAIN_POLICY_PROPOSALS: &str = "get_foreign_chain_policy_proposals";
pub const ALLOWED_DOCKER_IMAGE_HASHES: &str = "allowed_docker_image_hashes";
pub const ALLOWED_LAUNCHER_COMPOSE_HASHES: &str = "allowed_launcher_compose_hashes";
pub const MIGRATION_INFO: &str = "migration_info";
