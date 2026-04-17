/// Generates a dummy [`near_mpc_contract_interface::types::Config`] with different values for each field.
pub fn dummy_config(value: u64) -> near_mpc_contract_interface::types::Config {
    near_mpc_contract_interface::types::Config {
        key_event_timeout_blocks: value,
        tee_upgrade_deadline_duration_seconds: value + 1,
        contract_upgrade_deposit_tera_gas: value + 2,
        sign_call_gas_attachment_requirement_tera_gas: value + 3,
        ckd_call_gas_attachment_requirement_tera_gas: value + 4,
        return_signature_and_clean_state_on_success_call_tera_gas: value + 5,
        return_ck_and_clean_state_on_success_call_tera_gas: value + 6,
        fail_on_timeout_tera_gas: value + 7,
        clean_tee_status_tera_gas: value + 8,
        clean_invalid_attestations_tera_gas: value + 9,
        cleanup_orphaned_node_migrations_tera_gas: value + 10,
        remove_non_participant_update_votes_tera_gas: value + 11,
        clean_foreign_chain_data_tera_gas: value + 12,
    }
}
