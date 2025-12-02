use crate::sandbox::{
    common::{init_with_candidates, CURRENT_CONTRACT_DEPLOY_DEPOSIT},
    upgrade_from_current_contract::current_contract_proposal,
};
use mpc_contract::update::UpdateId;

#[tokio::test]
async fn test_high_gas_deposit_config_value_passes_upgrades() {
    let (saw_completion, saw_failure) = run_upgrade_scenario(1).await;

    assert!(saw_completion, "Update never completed");
    assert!(!saw_failure, "Upgrade unexpectedly failed");
}

#[tokio::test]
async fn test_zero_gas_deposit_config_value_fails_upgrades() {
    let (saw_completion, saw_failure) = run_upgrade_scenario(0).await;

    assert!(
        saw_failure,
        "Upgrade never failed; expected failure with zero gas"
    );
    assert!(
        !saw_completion,
        "Upgrade unexpectedly completed with zero gas"
    );
}

async fn run_upgrade_scenario(min_gas: u64) -> (bool, bool) {
    let init_config = contract_interface::types::InitConfig {
        contract_upgrade_deposit_tera_gas: Some(min_gas),
        ..Default::default()
    };

    let (_, contract, accounts) = init_with_candidates(vec![], Some(init_config), 3).await;

    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(current_contract_proposal())
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();

    assert!(execution.is_success());
    let proposal_id: UpdateId = execution.json().unwrap();

    let mut saw_completion = false;
    let mut saw_failure = false;

    for voter in accounts {
        let execution = voter
            .call(contract.id(), "vote_update")
            .args_json(serde_json::json!({ "id": proposal_id }))
            .max_gas()
            .transact()
            .await
            .unwrap();

        dbg!(&execution);

        if !execution.is_success() {
            saw_failure = true;
            break;
        }

        let update_completed: bool = execution.json().expect("Vote cast was unsuccessful");

        if update_completed {
            saw_completion = true;
            break;
        }
    }

    (saw_completion, saw_failure)
}

#[tokio::test]
async fn contract_configuration_can_be_set_on_initialization() {
    let init_config = contract_interface::types::InitConfig {
        key_event_timeout_blocks: Some(11),
        tee_upgrade_deadline_duration_seconds: Some(22),
        contract_upgrade_deposit_tera_gas: Some(33),
        sign_call_gas_attachment_requirement_tera_gas: Some(44),
        ckd_call_gas_attachment_requirement_tera_gas: Some(55),
        return_signature_and_clean_state_on_success_call_tera_gas: Some(66),
        return_ck_and_clean_state_on_success_call_tera_gas: Some(77),
        fail_on_timeout_tera_gas: Some(88),
        clean_tee_status_tera_gas: Some(99),
        cleanup_orphaned_node_migrations_tera_gas: Some(11),
        remove_non_participant_update_votes_tera_gas: Some(12),
    };

    let (_, contract, _) = init_with_candidates(vec![], Some(init_config.clone()), 2).await;

    let stored_config: contract_interface::types::InitConfig =
        contract.view("config").await.unwrap().json().unwrap();

    assert_eq!(stored_config, init_config);
}
