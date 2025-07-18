pub mod common;
use common::{init_env_secp256k1, vote_update_till_completion, CONTRACT_FILE_PATH};
use mpc_contract::config::Config;
use mpc_contract::state::ProtocolContractState;
use mpc_contract::update::{ProposeUpdateArgs, UpdateId};
use near_workspaces::types::NearToken;

pub fn dummy_contract() -> ProposeUpdateArgs {
    ProposeUpdateArgs {
        code: Some(vec![1, 2, 3]),
        config: None,
    }
}

pub fn current_contract() -> ProposeUpdateArgs {
    let new_wasm = std::fs::read(CONTRACT_FILE_PATH).unwrap();
    ProposeUpdateArgs {
        code: Some(new_wasm),
        config: None,
    }
}

pub fn invalid_contract() -> ProposeUpdateArgs {
    let new_wasm = b"invalid wasm".to_vec();
    ProposeUpdateArgs {
        code: Some(new_wasm),
        config: None,
    }
}

/// This is the current deposit required for a contract deploy. This is subject to change but make
/// sure that it's not larger than 2mb. We can go up to 4mb technically but our contract should
/// not be getting that big.
const CURRENT_CONTRACT_DEPLOY_DEPOSIT: NearToken = NearToken::from_millinear(9750);

#[tokio::test]
async fn test_propose_contract_max_size_upload() {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
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
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    // contract should not be able to propose updates unless it's a part of the participant/voter set.
    let execution = contract
        .call("propose_update")
        .args_borsh((dummy_contract(),))
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
    let new_config = Config {
        key_event_timeout_blocks: 20,
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

    let old_config: serde_json::Value = contract.view("config").await.unwrap().json().unwrap();
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
            .transact()
            .await
            .unwrap();

        // NOTE: since 2 out of 3 participants are required to pass a proposal, having the third one also
        // vote should fail.
        if i < 2 {
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
    let new_config = serde_json::json!(new_config);
    // check that the proposal executed since the threshold got changed.
    let config: serde_json::Value = contract.view("config").await.unwrap().json().unwrap();
    assert_ne!(config, old_config);
    assert_eq!(config, new_config);
}

#[tokio::test]
async fn test_propose_update_contract() {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((current_contract(),))
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_id: UpdateId = execution.json().unwrap();
    vote_update_till_completion(&contract, &accounts, &proposal_id).await;

    // Try calling into state and see if it works.
    let execution = accounts[0]
        .call(contract.id(), "state")
        .transact()
        .await
        .unwrap();

    dbg!(&execution);

    let state: ProtocolContractState = execution.json().unwrap();
    dbg!(state);
}

#[tokio::test]
async fn test_invalid_contract_deploy() {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    const CONTRACT_DEPLOY: NearToken = NearToken::from_near(1);

    // Let's propose a contract update instead now.
    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((invalid_contract(),))
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
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    const PROPOSAL_COUNT: usize = 3;
    let mut proposals = Vec::with_capacity(PROPOSAL_COUNT);
    // Try to propose multiple updates to check if they are being proposed correctly
    // and that we can have many at once living in the contract state.
    for i in 0..PROPOSAL_COUNT {
        let execution = accounts[i % accounts.len()]
            .call(contract.id(), "propose_update")
            .args_borsh((current_contract(),))
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
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    let dummy_config = Config {
        key_event_timeout_blocks: 20,
    };

    // Can not propose update both to code and config
    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((dummy_contract(), dummy_config))
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
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    for _ in 0..3 {
        let execution = accounts[0]
            .call(contract.id(), "propose_update")
            .args_borsh((current_contract(),))
            .max_gas()
            .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
            .transact()
            .await
            .unwrap();
        dbg!(&execution);
        assert!(execution.is_success());
        let proposal_id: UpdateId = execution.json().unwrap();
        vote_update_till_completion(&contract, &accounts, &proposal_id).await;

        // Try calling into state and see if it works.
        let execution = accounts[0]
            .call(contract.id(), "state")
            .transact()
            .await
            .unwrap();

        dbg!(&execution);

        let state: ProtocolContractState = execution.json().unwrap();
        dbg!(state);
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
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    dbg!(contract.id());

    let execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh((current_contract(),))
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
        .args_borsh((current_contract(),))
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
