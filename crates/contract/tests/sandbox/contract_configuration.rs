use crate::sandbox::utils::transactions::CallMpcContract;
use crate::sandbox::{
    common::{SandboxTestSetup, vote_update_till_approved},
    upgrade_from_current_contract::current_contract_update,
};
use near_mpc_contract_interface::method_names;
use near_mpc_sdk::update::hash;

#[tokio::test]
async fn test_high_gas_deposit_config_value_passes_upgrades() {
    assert!(run_upgrade_scenario(1).await, "Upgrade unexpectedly failed");
}

#[tokio::test]
async fn test_zero_gas_deposit_config_value_fails_upgrades() {
    assert!(
        !run_upgrade_scenario(0).await,
        "Upgrade unexpectedly completed with zero gas"
    );
}

async fn run_upgrade_scenario(min_gas: u64) -> bool {
    let init_config = near_mpc_contract_interface::types::InitConfig {
        contract_upgrade_deposit_tera_gas: Some(min_gas),
        ..Default::default()
    };

    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_init_config(init_config)
        .with_number_of_participants(3)
        .build()
        .await;

    let update = current_contract_update();
    vote_update_till_approved(&contract, &mpc_signer_accounts, hash(&update)).await;

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();
    dbg!(&execution);

    execution.is_success()
}

#[tokio::test]
async fn contract_configuration_can_be_set_on_initialization() {
    let init_config = near_mpc_contract_interface::types::InitConfig {
        attestation_storage_fee_millinear: Some(20),
        key_event_timeout_blocks: Some(11),
        tee_upgrade_deadline_duration_seconds: Some(22),
        contract_upgrade_deposit_tera_gas: Some(33),
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
        // Must satisfy `Config::validate` (>= DEFAULT_EXPIRATION_DURATION_SECONDS).
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

    let stored_config: near_mpc_contract_interface::types::InitConfig = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(stored_config, init_config);
}
