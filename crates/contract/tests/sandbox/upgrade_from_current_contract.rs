use crate::sandbox::{
    common::{
        execute_key_generation_and_add_random_state, init_env, init_with_candidates,
        propose_and_vote_contract_binary, vote_update_till_completion, SandboxTestSetup,
    },
    utils::{
        consts::{
            ALL_CURVES, CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_VOTE_BEFORE_THRESHOLD,
            GAS_FOR_VOTE_UPDATE, MAX_GAS_FOR_THRESHOLD_VOTE, PARTICIPANT_LEN,
        },
        contract_build::{current_contract, large_contract, migration_contract},
        interface::IntoContractType,
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_state,
        },
    },
};
use mpc_contract::update::{
    ProposeUpdateArgs, StartContractUploadArgs, UpdateId, UploadContractChunkArgs,
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::ProtocolContractState;
use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract};
use rand_core::OsRng;
use sha2::Digest;

/// Upload contract code via the chunked upload flow and return the resulting UpdateId.
async fn chunked_upload_contract(
    account: &Account,
    contract: &Contract,
    code: &[u8],
    deposit_per_chunk: NearToken,
) -> UpdateId {
    account
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
        account
            .call(contract.id(), method_names::UPLOAD_CONTRACT_CHUNK)
            .args_borsh(UploadContractChunkArgs {
                data: chunk.to_vec(),
            })
            .max_gas()
            .deposit(deposit_per_chunk)
            .transact()
            .await
            .unwrap()
            .into_result()
            .expect("upload_contract_chunk failed");
    }

    let finalize = account
        .call(contract.id(), method_names::FINALIZE_CONTRACT_UPLOAD)
        .args_borsh(())
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap();
    assert!(finalize.is_success(), "finalize_contract_upload failed");
    finalize.json().unwrap()
}

#[tokio::test]
async fn test_propose_contract_max_size_upload() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;
    dbg!(contract.id());

    // check that we can propose an update with a large contract size via chunked upload.
    let large_code = vec![0u8; 1536 * 1024 - 400];
    let _update_id = chunked_upload_contract(
        &mpc_signer_accounts[0],
        &contract,
        &large_code,
        NearToken::from_near(40),
    )
    .await;
}

#[tokio::test]
async fn test_propose_update_config() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await;
    dbg!(contract.id());

    // contract should not be able to propose updates unless it's a part of the participant/voter set.
    let dummy_config = near_mpc_contract_interface::types::Config {
        key_event_timeout_blocks: 1,
        tee_upgrade_deadline_duration_seconds: 2,
        contract_upgrade_deposit_tera_gas: 3,
        sign_call_gas_attachment_requirement_tera_gas: 4,
        ckd_call_gas_attachment_requirement_tera_gas: 5,
        return_signature_and_clean_state_on_success_call_tera_gas: 6,
        return_ck_and_clean_state_on_success_call_tera_gas: 7,
        fail_on_timeout_tera_gas: 8,
        clean_tee_status_tera_gas: 9,
        cleanup_orphaned_node_migrations_tera_gas: 10,
        remove_non_participant_update_votes_tera_gas: 11,
    };
    let execution = contract
        .call(method_names::PROPOSE_UPDATE)
        .args_borsh((ProposeUpdateArgs {
            config: dummy_config,
        },))
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
    let new_config = near_mpc_contract_interface::types::Config {
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

    let mut proposals = Vec::with_capacity(mpc_signer_accounts.len());
    for account in &mpc_signer_accounts {
        let propose_execution = account
            .call(contract.id(), method_names::PROPOSE_UPDATE)
            .args_borsh((ProposeUpdateArgs {
                config: new_config.clone(),
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

    let old_config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    let state: ProtocolContractState = get_state(&contract).await;

    // check that each participant can vote on a singular proposal and have it reflect changes:
    let first_proposal = &proposals[0];
    for (i, voter) in mpc_signer_accounts.iter().enumerate() {
        dbg!(voter.id());
        let execution = voter
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({
                "id": first_proposal,
            }))
            .gas(GAS_FOR_VOTE_UPDATE)
            .transact()
            .await
            .unwrap();

        // NOTE: since threshold out of total participants are required to pass a proposal, having the `threshold+1` one also
        // vote should fail.
        if i < threshold.0 as usize {
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
    let config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_ne!(config, old_config);
    assert_eq!(config, new_config);
}

#[tokio::test]
async fn test_propose_update_contract() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;
    propose_and_vote_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;
}

#[tokio::test]
async fn test_invalid_contract_deploy() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;
    dbg!(contract.id());

    const CONTRACT_DEPLOY: NearToken = NearToken::from_near(1);

    // Let's propose an invalid contract update via chunked upload.
    let invalid_wasm = b"invalid wasm".to_vec();
    let proposal_id = chunked_upload_contract(
        &mpc_signer_accounts[0],
        &contract,
        &invalid_wasm,
        CONTRACT_DEPLOY,
    )
    .await;
    vote_update_till_completion(&contract, &mpc_signer_accounts, &proposal_id).await;

    // Try calling into state and see if it works after the contract updates with an invalid
    // contract. It will fail in `migrate` so a state rollback on the contract code should have
    // happened.
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::STATE)
        .transact()
        .await
        .unwrap();

    dbg!(&execution);
    let state: ProtocolContractState = execution.json().unwrap();
    dbg!(state);
}

// TODO(#496): Investigate flakiness of this test
#[tokio::test]
async fn test_propose_update_contract_many() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;
    dbg!(contract.id());

    const PROPOSAL_COUNT: usize = 2;
    let mut proposals = Vec::with_capacity(PROPOSAL_COUNT);
    // Try to propose multiple updates via chunked upload to check if they are being
    // proposed correctly and that we can have many at once living in the contract state.
    for i in 0..PROPOSAL_COUNT {
        let account = &mpc_signer_accounts[i % mpc_signer_accounts.len()];
        let proposal_id = chunked_upload_contract(
            account,
            &contract,
            current_contract(),
            CURRENT_CONTRACT_DEPLOY_DEPOSIT,
        )
        .await;
        proposals.push(proposal_id);
    }

    // Vote for the last proposal
    vote_update_till_completion(&contract, &mpc_signer_accounts, proposals.last().unwrap()).await;

    // Ensure all proposals are removed after update
    for proposal in proposals {
        let voter = mpc_signer_accounts.first().unwrap();
        let execution = voter
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({
                "id": proposal,
            }))
            .gas(GAS_FOR_VOTE_UPDATE)
            .transact()
            .await
            .unwrap();
        dbg!(&execution);

        assert!(execution.is_failure());
    }

    // Let's check that we can call into the state and see all the proposals.
    let state: ProtocolContractState = get_state(&contract).await;
    dbg!(state);
}

/// Regression test for issue #1617: ensures that voting on contract updates (before reaching
/// threshold) is cheap.
#[tokio::test]
async fn test_vote_update_gas_before_threshold() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    let proposal_id = chunked_upload_contract(
        &mpc_signer_accounts[0],
        &contract,
        current_contract(),
        CURRENT_CONTRACT_DEPLOY_DEPOSIT,
    )
    .await;

    // Cast votes until threshold is reached (need 6 total votes)
    for (idx, account) in mpc_signer_accounts[1..=5].iter().enumerate() {
        let execution = account
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({
                "id": proposal_id,
            }))
            .gas(GAS_FOR_VOTE_BEFORE_THRESHOLD)
            .transact()
            .await
            .unwrap();

        let gas_burnt = execution.total_gas_burnt;

        assert!(execution.is_success());

        let update_occurred: bool = execution.json().unwrap();
        assert!(!update_occurred);

        assert!(
            gas_burnt.as_tgas() <= GAS_FOR_VOTE_BEFORE_THRESHOLD.as_tgas(),
            "Gas usage for vote {} ({} TGas) should be <= {} TGas",
            idx + 1,
            gas_burnt.as_tgas(),
            GAS_FOR_VOTE_BEFORE_THRESHOLD.as_tgas()
        );
    }

    // Cast the threshold vote (6th vote) that will trigger the update
    let threshold_execution = mpc_signer_accounts[6]
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(serde_json::json!({
            "id": proposal_id,
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();

    let threshold_gas_burnt = threshold_execution.total_gas_burnt;

    assert!(threshold_execution.is_success());

    let update_occurred: bool = threshold_execution.json().unwrap();
    assert!(update_occurred);

    assert!(
        threshold_gas_burnt.as_tgas() <= MAX_GAS_FOR_THRESHOLD_VOTE.as_tgas(),
        "Gas usage for threshold vote ({} TGas) should be <= {} TGas",
        threshold_gas_burnt.as_tgas(),
        MAX_GAS_FOR_THRESHOLD_VOTE.as_tgas()
    );
}

#[tokio::test]
async fn test_propose_incorrect_updates() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;
    dbg!(contract.id());

    // Sending garbage args to propose_update should fail
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::PROPOSE_UPDATE)
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
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, number_of_participants).await;
    dbg!(contract.id());
    let number_of_updates = 3;
    for _ in 0..number_of_updates {
        propose_and_vote_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;
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
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, number_of_participants).await;
    dbg!(contract.id());

    let proposal_a = chunked_upload_contract(
        &mpc_signer_accounts[0],
        &contract,
        current_contract(),
        CURRENT_CONTRACT_DEPLOY_DEPOSIT,
    )
    .await;

    let proposal_b = chunked_upload_contract(
        &mpc_signer_accounts[0],
        &contract,
        current_contract(),
        CURRENT_CONTRACT_DEPLOY_DEPOSIT,
    )
    .await;

    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(serde_json::json!({
            "id": proposal_a,
        }))
        .gas(GAS_FOR_VOTE_UPDATE)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(serde_json::json!({
            "id": proposal_b,
        }))
        .gas(GAS_FOR_VOTE_UPDATE)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = mpc_signer_accounts[1]
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(serde_json::json!({
            "id": proposal_a,
        }))
        .gas(GAS_FOR_VOTE_UPDATE)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = mpc_signer_accounts[1]
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(serde_json::json!({
            "id": proposal_b,
        }))
        .gas(GAS_FOR_VOTE_UPDATE)
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
    let (worker, contract, mpc_signer_accounts, _) =
        init_with_candidates(vec![], None, PARTICIPANT_LEN).await;

    let participants = assert_running_return_participants(&contract)
        .await
        .expect("Contract must be in running state.");

    execute_key_generation_and_add_random_state(
        &mpc_signer_accounts,
        participants.into_contract_type(),
        &contract,
        &worker,
        &mut OsRng,
    )
    .await;
    propose_and_vote_contract_binary(&mpc_signer_accounts, &contract, migration_contract()).await;
}

#[tokio::test]
async fn migration_function_rejects_external_callers() {
    let number_of_participants: usize = 2;
    let (_worker, contract, mpc_signer_accounts, _) =
        init_with_candidates(vec![], None, number_of_participants).await;

    let execution_error = mpc_signer_accounts[0]
        .call(contract.id(), method_names::MIGRATE)
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

// ──── Chunked upload integration tests ────

/// Verifies the full chunked upload flow: start → multi-chunk upload → finalize → vote → deploy.
#[tokio::test]
async fn test_chunked_upload_multi_chunk_and_deploy() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    let code = current_contract();
    assert!(code.len() > 1024, "contract binary should be non-trivial");

    // Upload in small chunks to exercise multi-chunk path
    let chunk_size = code.len() / 3 + 1; // ~3 chunks

    mpc_signer_accounts[0]
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

    let mut chunks_uploaded = 0;
    for chunk in code.chunks(chunk_size) {
        mpc_signer_accounts[0]
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
        chunks_uploaded += 1;
    }
    assert!(chunks_uploaded >= 3, "should have uploaded at least 3 chunks");

    let finalize = mpc_signer_accounts[0]
        .call(contract.id(), method_names::FINALIZE_CONTRACT_UPLOAD)
        .args_borsh(())
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap();
    assert!(finalize.is_success(), "finalize_contract_upload failed");
    let proposal_id: UpdateId = finalize.json().unwrap();

    // Vote and deploy
    vote_update_till_completion(&contract, &mpc_signer_accounts, &proposal_id).await;

    // Verify deployed code matches what we uploaded
    let deployed = contract.view_code().await.unwrap();
    assert_eq!(
        sha2::Sha256::digest(code).as_slice(),
        sha2::Sha256::digest(&deployed).as_slice(),
        "deployed binary must match uploaded code"
    );
}

/// Non-voter cannot start a chunked upload.
#[tokio::test]
async fn test_chunked_upload_non_voter_rejected() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts: _,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    // The contract's own account is not a voter
    let execution = contract
        .call(method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 100 })
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap();
    assert!(
        execution.is_failure(),
        "non-voter should be rejected from start_contract_upload"
    );
}

/// Starting a second upload without clearing the first should fail.
#[tokio::test]
async fn test_chunked_upload_double_start_rejected() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    // First start succeeds
    mpc_signer_accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 100 })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("first start should succeed");

    // Second start without clear_staged_contract should fail
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 200 })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap();
    assert!(
        execution.is_failure(),
        "second start_contract_upload without clearing should fail"
    );
}

/// Uploading a chunk that exceeds declared total_size should fail.
#[tokio::test]
async fn test_chunked_upload_exceeding_total_size_rejected() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    mpc_signer_accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 10 })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("start should succeed");

    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::UPLOAD_CONTRACT_CHUNK)
        .args_borsh(UploadContractChunkArgs {
            data: vec![0u8; 20], // exceeds total_size of 10
        })
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    assert!(
        execution.is_failure(),
        "chunk exceeding total_size should be rejected"
    );
}

/// Finalizing an incomplete upload should fail.
#[tokio::test]
async fn test_chunked_upload_finalize_incomplete_rejected() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    mpc_signer_accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 100 })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("start should succeed");

    // Upload only 50 of 100 bytes
    mpc_signer_accounts[0]
        .call(contract.id(), method_names::UPLOAD_CONTRACT_CHUNK)
        .args_borsh(UploadContractChunkArgs {
            data: vec![0u8; 50],
        })
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("partial upload should succeed");

    // Finalize should fail because upload is incomplete
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::FINALIZE_CONTRACT_UPLOAD)
        .args_borsh(())
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap();
    assert!(
        execution.is_failure(),
        "finalize with incomplete upload should fail"
    );
}

/// clear_staged_contract should allow starting a new upload.
#[tokio::test]
async fn test_clear_staged_contract_allows_restart() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    // Start an upload
    mpc_signer_accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 100 })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("start should succeed");

    // Clear it
    mpc_signer_accounts[0]
        .call(contract.id(), method_names::CLEAR_STAGED_CONTRACT)
        .max_gas()
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("clear should succeed");

    // Should be able to start a new one
    mpc_signer_accounts[0]
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs { total_size: 200 })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect("restart after clear should succeed");
}

/// Upload and deploy a ~2 MiB contract via chunked upload to verify that binaries
/// exceeding the 1.5 MiB RPC limit can be proposed and deployed.
#[tokio::test]
async fn test_chunked_upload_large_contract() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_CURVES, PARTICIPANT_LEN).await;

    let code = large_contract();
    assert!(
        code.len() > 1_500_000,
        "large contract should exceed the 1.5 MiB RPC limit, got {} bytes",
        code.len()
    );

    // Storage cost is ~10 NEAR per MiB. Use 11 NEAR per chunk (1 MiB) to have margin.
    let proposal_id = chunked_upload_contract(
        &mpc_signer_accounts[0],
        &contract,
        code,
        NearToken::from_near(11),
    )
    .await;

    // Use max_gas for votes since deploying a 2 MiB contract is gas-intensive.
    for voter in &mpc_signer_accounts {
        let execution = voter
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({ "id": proposal_id }))
            .max_gas()
            .transact()
            .await
            .unwrap();

        let update_occurred: bool = execution.json().expect("Vote cast was unsuccessful");
        if update_occurred {
            // Verify the deployed code matches what we uploaded
            let deployed = contract.view_code().await.unwrap();
            assert_eq!(
                sha2::Sha256::digest(code).as_slice(),
                sha2::Sha256::digest(&deployed).as_slice(),
                "deployed binary must match the large contract we uploaded"
            );
            return;
        }
    }
    panic!("Update never completed");
}
