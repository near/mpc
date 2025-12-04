use crate::sandbox::common::{
    assert_running_return_participants, assert_running_return_threshold, current_contract,
    execute_key_generation_and_add_random_state, init_env, init_with_candidates,
    migration_contract, propose_and_vote_contract_binary, vote_update_till_completion,
    CURRENT_CONTRACT_DEPLOY_DEPOSIT, PARTICIPANT_LEN,
};
use mpc_contract::primitives::domain::SignatureScheme;
use mpc_contract::state::ProtocolContractState;
use mpc_contract::update::{ProposeUpdateArgs, UpdateId};
use near_workspaces::types::NearToken;
use rand_core::OsRng;

pub fn dummy_contract_proposal() -> ProposeUpdateArgs {
    ProposeUpdateArgs {
        code: Some(vec![1, 2, 3]),
        config: None,
    }
}

pub fn invalid_contract_proposal() -> ProposeUpdateArgs {
    let new_wasm = b"invalid wasm".to_vec();
    ProposeUpdateArgs {
        code: Some(new_wasm),
        config: None,
    }
}

pub fn current_contract_proposal() -> ProposeUpdateArgs {
    ProposeUpdateArgs {
        code: Some(current_contract().to_vec()),
        config: None,
    }
}

#[tokio::test]
async fn test_propose_contract_max_size_upload() {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    dbg!(contract.id());

    // check that we can propose an update with the maximum contract size.
    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((ProposeUpdateArgs {
            code: Some(vec![0; 1536 * 1024 - 224]), //3900 seems to not work locally
            config: None,
        },))
        .max_gas()
        .deposit(NearToken::from_near(40))
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(
        execution.is_success(),
        "Failed to propose update with our highest contract size"
    );
}

#[tokio::test]
async fn test_propose_update_config() {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await;
    dbg!(contract.id());

    // contract should not be able to propose updates unless it's a part of the participant/voter set.
    let execution = contract
        .call("propose_update")
        .args_borsh((dummy_contract_proposal(),))
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution
        .into_result()
        .unwrap_err()
        .to_string()
        .contains("not a voter"));

    // have each participant propose a new update:
    let new_config = contract_interface::types::Config {
        key_event_timeout_blocks: 11,
        tee_upgrade_deadline_duration_seconds: 22,
        contract_upgrade_deposit_tera_gas: 33,
        sign_call_gas_attachment_requirement_tera_gas: 44,
        ckd_call_gas_attachment_requirement_tera_gas: 55,
        return_signature_and_clean_state_on_success_call_tera_gas: 66,
        return_ck_and_clean_state_on_success_call_tera_gas: 77,
        fail_on_timeout_tera_gas: 88,
        clean_tee_status_tera_gas: 99,
        cleanup_orphaned_node_migrations_tera_gas: 11,
        remove_non_participant_update_votes_tera_gas: 12,
    };

    let mut proposals = Vec::with_capacity(accounts.len());
    for account in &accounts {
        let propose_execution = account
            .call(contract.id(), "propose_update")
            .args_borsh((ProposeUpdateArgs {
                code: None,
                config: Some(new_config.clone()),
            },))
            .deposit(NearToken::from_millinear(100))
            .transact()
            .await
            .unwrap();
        dbg!(&propose_execution);
        assert!(propose_execution.is_success());
        let proposal_id: UpdateId = propose_execution.json().unwrap();
        dbg!(&proposal_id);
        proposals.push(proposal_id);
    }

    let old_config: contract_interface::types::Config =
        contract.view("config").await.unwrap().json().unwrap();
    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();

    // check that each participant can vote on a singular proposal and have it reflect changes:
    let first_proposal = &proposals[0];
    for (i, voter) in accounts.iter().enumerate() {
        dbg!(voter.id());
        let execution = voter
            .call(contract.id(), "vote_update")
            .args_json(serde_json::json!({
                "id": first_proposal,
            }))
            .max_gas()
            .transact()
            .await
            .unwrap();

        // NOTE: since threshold out of total participants are required to pass a proposal, having the `threshold+1` one also
        // vote should fail.
        if i < threshold.value() as usize {
            assert!(
                execution.is_success(),
                "execution should have succeeded: {state:#?}\n{execution:#?}"
            );
        } else {
            assert!(
                execution.is_failure(),
                "execution should have failed: {state:#?}\n{execution:#?}"
            );
        }
    }
    // check that the proposal executed since the threshold got changed.
    let config: contract_interface::types::Config =
        contract.view("config").await.unwrap().json().unwrap();

    assert_ne!(config, old_config);
    assert_eq!(config, new_config);
}

#[tokio::test]
async fn test_propose_update_contract() {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    propose_and_vote_contract_binary(&accounts, &contract, current_contract()).await;
}

#[tokio::test]
async fn test_invalid_contract_deploy() {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    dbg!(contract.id());

    const CONTRACT_DEPLOY: NearToken = NearToken::from_near(1);

    // Let's propose a contract update instead now.
    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((invalid_contract_proposal(),))
        .max_gas()
        .deposit(CONTRACT_DEPLOY)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_id: UpdateId = execution.json().unwrap();
    vote_update_till_completion(&contract, &accounts, &proposal_id).await;

    // Try calling into state and see if it works after the contract updates with an invalid
    // contract. It will fail in `migrate` so a state rollback on the contract code should have
    // happened.
    let execution = accounts[0]
        .call(contract.id(), "state")
        .transact()
        .await
        .unwrap();

    dbg!(&execution);
    let state: ProtocolContractState = execution.json().unwrap();
    dbg!(state);
}

// TODO(#496) Investigate flakiness of this test
#[tokio::test]
async fn test_propose_update_contract_many() {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    dbg!(contract.id());

    const PROPOSAL_COUNT: usize = 3;
    let mut proposals = Vec::with_capacity(PROPOSAL_COUNT);
    // Try to propose multiple updates to check if they are being proposed correctly
    // and that we can have many at once living in the contract state.
    for i in 0..PROPOSAL_COUNT {
        let execution = accounts[i % accounts.len()]
            .call(contract.id(), "propose_update")
            .args_borsh(current_contract_proposal())
            .max_gas()
            .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
            .transact()
            .await
            .unwrap();

        assert!(
            execution.is_success(),
            "failed to propose update [i={i}]; {execution:#?}"
        );
        let proposal_id = execution.json().expect("unable to convert into UpdateId");
        proposals.push(proposal_id);
    }

    // Vote for the last proposal
    vote_update_till_completion(&contract, &accounts, proposals.last().unwrap()).await;

    // Ensure all proposals are removed after update
    for proposal in proposals {
        let voter = accounts.first().unwrap();
        let execution = voter
            .call(contract.id(), "vote_update")
            .args_json(serde_json::json!({
                "id": proposal,
            }))
            .max_gas()
            .transact()
            .await
            .unwrap();
        dbg!(&execution);

        assert!(execution.is_failure());
    }

    // Let's check that we can call into the state and see all the proposals.
    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    dbg!(state);
}

#[tokio::test]
async fn test_propose_incorrect_updates() {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    dbg!(contract.id());

    let dummy_config = contract_interface::types::InitConfig::default();

    // Can not propose update both to code and config
    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((dummy_contract_proposal(), dummy_config))
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());

    // Should propose something
    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(())
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());
}

/// Contract update include some logic regarding state clean-up,
/// thus we want to test whether some problem builds up eventually.
#[tokio::test]
async fn many_sequential_updates() {
    let number_of_participants = PARTICIPANT_LEN;
    let (_, contract, accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], number_of_participants).await;
    dbg!(contract.id());
    let number_of_updates = 3;
    for _ in 0..number_of_updates {
        propose_and_vote_contract_binary(&accounts, &contract, current_contract()).await;
    }
}

/// There are:
///     * two proposals: A and B
///     * three participants (Alice, Bob, Carl), with a threshold two
/// What happens:
///     1. Alice votes for A
///     2. Alice votes for B
///     3. Bob votes for A -> Update for A _should not_ be triggered
///     4. Bob votes for B -> Update for B is triggered
#[tokio::test]
async fn only_one_vote_from_participant() {
    let number_of_participants = 3;
    let (_, contract, accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], number_of_participants).await;
    dbg!(contract.id());

    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(current_contract_proposal())
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_a: UpdateId = execution.json().unwrap();

    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(current_contract_proposal())
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_b: UpdateId = execution.json().unwrap();

    let execution = accounts[0]
        .call(contract.id(), "vote_update")
        .args_json(serde_json::json!({
            "id": proposal_a,
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = accounts[0]
        .call(contract.id(), "vote_update")
        .args_json(serde_json::json!({
            "id": proposal_b,
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = accounts[1]
        .call(contract.id(), "vote_update")
        .args_json(serde_json::json!({
            "id": proposal_a,
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = accounts[1]
        .call(contract.id(), "vote_update")
        .args_json(serde_json::json!({
            "id": proposal_b,
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(update_occurred);
}

/// Tests that we can upgrade the current contract to a new binary. The new contract binary used is
/// the migration contract, [`migration_contract`].
#[tokio::test]
async fn update_from_current_contract_to_migration_contract() {
    // We don't add any initial domains on init, since we will domains
    // in add_dummy_state_and_pending_sign_requests call below.
    let (worker, contract, accounts) = init_with_candidates(vec![], None, PARTICIPANT_LEN).await;

    let participants = assert_running_return_participants(&contract)
        .await
        .expect("Contract must be in running state.");

    execute_key_generation_and_add_random_state(
        &accounts,
        participants,
        &contract,
        &worker,
        &mut OsRng,
    )
    .await;
    propose_and_vote_contract_binary(&accounts, &contract, migration_contract()).await;
}

#[tokio::test]
async fn migration_function_rejects_external_callers() {
    let (_worker, contract, accounts) = init_with_candidates(vec![], None, 2).await;

    let execution_error = accounts[0]
        .call(contract.id(), "migrate")
        .max_gas()
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect_err("method is private and not callable from participant account.");

    let error_message = format!("{:?}", execution_error);

    let expected_error_message = "Smart contract panicked: Method migrate is private";

    assert!(
        error_message.contains(expected_error_message),
        "migrate call was accepted by external caller. expected method to be private. {:?}",
        error_message
    )
}
