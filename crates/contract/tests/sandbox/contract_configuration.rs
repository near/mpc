use crate::sandbox::{
    common::init_with_candidates,
    utils::{
        consts::{CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_VOTE_UPDATE},
        contract_build::current_contract,
    },
};
use mpc_contract::update::{StartContractUploadArgs, UpdateId, UploadContractChunkArgs};
use near_mpc_contract_interface::method_names;
use near_workspaces::types::NearToken;

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
    let init_config = near_mpc_contract_interface::types::InitConfig {
        contract_upgrade_deposit_tera_gas: Some(min_gas),
        ..Default::default()
    };

    let number_of_participants: usize = 3;
    let (_, contract, accounts, _) =
        init_with_candidates(vec![], Some(init_config), number_of_participants).await;

    let code = current_contract();

    accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs {
            total_size: code.len() as u64,
        })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("start_contract_upload failed");

    const CHUNK_SIZE: usize = 1024 * 1024;
    for chunk in code.chunks(CHUNK_SIZE) {
        accounts[0]
            .call(contract.id(), method_names::UPLOAD_CONTRACT_CHUNK)
            .args_borsh(UploadContractChunkArgs {
                data: chunk.to_vec(),
            })
            .max_gas()
            .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
            .transact()
            .await
            .unwrap()
            .into_result()
            .expect("upload_contract_chunk failed");
    }

    let finalize = accounts[0]
        .call(contract.id(), method_names::FINALIZE_CONTRACT_UPLOAD)
        .args_borsh(())
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap();
    assert!(finalize.is_success(), "finalize_contract_upload failed");
    let proposal_id: UpdateId = finalize.json().unwrap();

    let mut saw_completion = false;
    let mut saw_failure = false;

    for voter in accounts {
        let execution = voter
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({ "id": proposal_id }))
            .gas(GAS_FOR_VOTE_UPDATE)
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
    let init_config = near_mpc_contract_interface::types::InitConfig {
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

    let number_of_participants: usize = 2;
    let (_, contract, _, _) =
        init_with_candidates(vec![], Some(init_config.clone()), number_of_participants).await;

    let stored_config: near_mpc_contract_interface::types::InitConfig = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(stored_config, init_config);
}
