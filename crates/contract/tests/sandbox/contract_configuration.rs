use crate::sandbox::{
    common::{init_with_candidates, CURRENT_CONTRACT_DEPLOY_DEPOSIT},
    upgrade_from_current_contract::current_contract_proposal,
};
use mpc_contract::{config::InitConfig, update::UpdateId};

#[tokio::test]
async fn test_high_gas_deposit_config_value_passes_upgrades() {
    let (saw_completion, saw_failure) = run_upgrade_scenario(Some(1)).await;

    assert!(saw_completion, "Update never completed");
    assert!(!saw_failure, "Upgrade unexpectedly failed");
}

#[tokio::test]
async fn test_zero_gas_deposit_config_value_fails_upgrades() {
    let (saw_completion, saw_failure) = run_upgrade_scenario(Some(0)).await;

    assert!(
        saw_failure,
        "Upgrade never failed; expected failure with zero gas"
    );
    assert!(
        !saw_completion,
        "Upgrade unexpectedly completed with zero gas"
    );
}

async fn run_upgrade_scenario(min_gas: Option<u64>) -> (bool, bool) {
    let init_config = InitConfig {
        vote_update_minimum_gas_attached_tera_gas: min_gas,
        ..Default::default()
    };

    let (_, contract, accounts) = init_with_candidates(vec![], init_config, 3).await;

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
