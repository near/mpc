use crate::sandbox::common::SandboxTestSetup;
use mpc_contract::primitives::test_utils::bogus_genesis_hash;
use near_mpc_contract_interface::types::BlockCount;

#[tokio::test]
async fn contract_configuration_can_be_set_on_initialization() {
    let init_config = near_mpc_contract_interface::types::InitConfig {
        attestation_storage_fee_millinear: Some(20),
        key_event_timeout_blocks: Some(BlockCount::from(11)),
        tee_upgrade_deadline_duration_seconds: Some(22),
        apply_contract_update_tera_gas: Some(33),
        sign_call_gas_attachment_requirement_tera_gas: Some(44),
        ckd_call_gas_attachment_requirement_tera_gas: Some(55),
        return_signature_and_clean_state_on_success_call_tera_gas: Some(66),
        return_ck_and_clean_state_on_success_call_tera_gas: Some(77),
        fail_on_timeout_tera_gas: Some(88),
        fail_attestation_submission_tera_gas: Some(89),
        clean_tee_status_tera_gas: Some(99),
        clean_invalid_attestations_tera_gas: Some(101),
        cleanup_orphaned_node_migrations_tera_gas: Some(11),
        remove_non_participant_update_votes_tera_gas: Some(12),
        clean_foreign_chain_data_tera_gas: Some(13),
        remove_non_participant_tee_verifier_votes_tera_gas: Some(14),
        verifier_tera_gas: Some(15),
        resolve_verification_tera_gas: Some(16),
        launcher_hash_unused_ttl_seconds: Some(14 * 24 * 60 * 60),
    };

    let SandboxTestSetup {
        worker: _worker,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_init_config(init_config.clone())
        .with_number_of_participants(2)
        .build()
        .await;

    let stored_config = contract.config().await.unwrap().value;
    let mut expected_config = serde_json::to_value(init_config).unwrap();
    expected_config["migration_genesis_hash"] = serde_json::Value::Null;
    assert_eq!(
        serde_json::to_value(stored_config).unwrap(),
        expected_config
    );
}

#[tokio::test]
#[expect(non_snake_case)]
async fn init__should_store_the_genesis_hash() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_number_of_participants(2)
        .build()
        .await;

    // When
    let genesis_hash = contract.genesis_hash().await.unwrap().value;

    // Then
    assert_eq!(genesis_hash, Some(bogus_genesis_hash()));
}
