pub mod common;

use anyhow::Result;
use near_workspaces::{Account, AccountId, Contract};
use serde_json::json;

use common::{
    check_call_success, gen_accounts, get_tee_participants, init_env_secp256k1,
    submit_participant_info,
};
use mpc_contract::{
    primitives::{
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
};
use mpc_primitives::hash::MpcDockerImageHash;
use test_utils::attestation::{mock_local_attestation, p2p_tls_key};

/// Helper function to set up contract with approved MPC hash
async fn setup_contract_with_approved_hash(
    contract: &Contract,
    accounts: &[Account],
) -> Result<()> {
    let hash = MpcDockerImageHash::from([
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
        0x78, 0x90,
    ]);

    for account in accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_code_hash")
                .args_json(json!({"code_hash": hash}))
                .max_gas()
                .transact()
                .await?,
        );
    }

    Ok(())
}

/// Integration test that validates the complete E2E flow of TEE cleanup after resharing.
///
/// This test:
/// 1. Sets up an initial participant set with TEE attestations
/// 2. Adds additional TEE participants (simulating stale data)
/// 3. Initiates a new resharing with a subset of the original participants
/// 4. Completes the resharing process by voting
/// 5. Verifies that vote_reshared triggered cleanup of stale TEE attestations
/// 6. Confirms only the new participant set remains in TEE state
#[tokio::test]
async fn test_tee_cleanup_after_full_resharing_flow() -> Result<()> {
    let (worker, contract, initial_accounts, _) = init_env_secp256k1(1).await;

    // Set up TEE attestations for all initial participants
    let tls_key = p2p_tls_key();
    let attestation = mock_local_attestation(true);
    setup_contract_with_approved_hash(&contract, &initial_accounts).await?;

    for account in &initial_accounts {
        let submission_result =
            submit_participant_info(account, &contract, &attestation, &tls_key).await?;
        assert!(submission_result);
    }

    // Verify TEE participants were added
    let initial_tee_participants = get_tee_participants(&contract).await?;
    assert_eq!(initial_tee_participants.len(), initial_accounts.len(),);

    // Create additional accounts to simulate stale participants
    let (stale_accounts, _) = gen_accounts(&worker, 2).await;

    // Add stale participants to TEE state
    for stale_account in &stale_accounts {
        let submission_result =
            submit_participant_info(stale_account, &contract, &attestation, &tls_key).await?;
        assert!(submission_result);
    }

    // Verify all participants are in TEE state (initial + stale)
    let all_tee_participants = get_tee_participants(&contract).await?;
    assert_eq!(
        all_tee_participants.len(),
        initial_accounts.len() + stale_accounts.len()
    );

    // Get current state to extract participant info
    let state: ProtocolContractState = contract.view("state").await?.json()?;
    let running_state = match state {
        ProtocolContractState::Running(running_state) => running_state,
        _ => panic!("Contract should be in running state initially"),
    };

    // Create subset for new parameters (2 out of 3 initial participants)
    let new_participant_accounts = &initial_accounts[0..2];

    // Get current participants to construct proper ThresholdParameters
    let current_participants = running_state.parameters.participants().clone();

    // Create new participants list with only the subset we want
    let mut new_participants = Participants::new();
    for account in new_participant_accounts {
        // Find the participant info for this account from current participants
        if let Some((_, _, participant_info)) = current_participants
            .participants()
            .iter()
            .find(|(account_id, _, _)| account_id == account.id())
        {
            new_participants
                .insert(account.id().clone(), participant_info.clone())
                .expect("Failed to insert participant");
        } else {
            panic!("Account {} not found in current participants", account.id());
        }
    }

    // Create proper ThresholdParameters
    let new_threshold_parameters =
        ThresholdParameters::new(new_participants, Threshold::new(2)).unwrap();

    // Use hardcoded prospective epoch ID for test simplicity
    // Based on the test setup, the contract starts with epoch 5, so next epoch is 6
    let prospective_epoch_id = 6;

    // Vote one by one and check the state after each vote
    for account in initial_accounts.iter() {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": prospective_epoch_id,
                    "proposal": new_threshold_parameters,
                }))
                .max_gas()
                .transact()
                .await?,
        );

        // Check if the state changed after this vote
        let post_vote_state: ProtocolContractState = contract.view("state").await?.json()?;
        match &post_vote_state {
            ProtocolContractState::Running(_) => {
                // Still in running state, continue voting
            }
            ProtocolContractState::Resharing(_) => {
                break; // Stop voting once we're in resharing
            }
            _ => {
                // Unexpected state
            }
        }
    }

    // Verify contract is now in resharing state
    let state: ProtocolContractState = contract.view("state").await?.json()?;

    let ProtocolContractState::Resharing(_resharing_state) = state else {
        panic!("Expected contract to be in Resharing state after voting");
    };

    // Use hardcoded key event ID for test simplicity
    let key_event_id = json!({
        "epoch_id": 6,
        "domain_id": 0,
        "attempt_id": 0,
    });

    // Start the reshare instance
    check_call_success(
        initial_accounts[0]
            .call(contract.id(), "start_reshare_instance")
            .args_json(json!({
                "key_event_id": key_event_id,
            }))
            .max_gas()
            .transact()
            .await?,
    );

    // Wait for all participants to vote for resharing
    let mut transition_happened = false;
    for account in initial_accounts.iter() {
        check_call_success(
            account
                .call(contract.id(), "vote_reshared")
                .args_json(json!({
                    "key_event_id": key_event_id,
                }))
                .max_gas()
                .transact()
                .await?,
        );

        // Check state after each vote_reshared
        let interim_state: ProtocolContractState = contract.view("state").await?.json()?;
        match interim_state {
            ProtocolContractState::Resharing(_) => {
                // Still in resharing state
            }
            ProtocolContractState::Running(_) => {
                transition_happened = true;
                break;
            }
            _ => {
                // Unexpected state
            }
        }
    }

    // Wait for the TEE cleanup promise to execute
    if transition_happened {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    // Verify contract is back to running state with new threshold
    let final_state: ProtocolContractState = contract.view("state").await?.json()?;
    let ProtocolContractState::Running(running_state) = final_state else {
        panic!(
            "Expected contract to be in Running state after resharing, but got: {:?}",
            final_state
        );
    };

    // Get current participants to compare
    let final_participants: Vec<AccountId> = running_state
        .parameters
        .participants()
        .participants()
        .iter()
        .map(|(account_id, _, _)| account_id.clone())
        .collect();

    // Verify only the new participants remain
    let expected_participants: Vec<AccountId> = new_participant_accounts
        .iter()
        .map(|acc| acc.id().clone())
        .collect();

    assert_eq!(final_participants.len(), new_participant_accounts.len());

    for expected_participant in &expected_participants {
        assert!(final_participants.contains(expected_participant));
    }

    // Verify TEE participants are properly cleaned up
    let tee_participants_after_cleanup: Vec<AccountId> = contract
        .call("get_tee_participants")
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?
        .json()?;

    // The expected behavior: TEE cleanup should remove non-participants, but keep participants
    let expected_remaining_tee_participants: Vec<AccountId> = new_participant_accounts
        .iter()
        .map(|acc| acc.id().clone())
        .collect();

    // Verify that the remaining TEE participants match exactly the new contract participants
    assert_eq!(
        tee_participants_after_cleanup.len(),
        expected_remaining_tee_participants.len(),
    );

    for expected_participant in &expected_remaining_tee_participants {
        assert!(tee_participants_after_cleanup.contains(expected_participant));
    }

    for tee_participant in &tee_participants_after_cleanup {
        assert!(expected_remaining_tee_participants.contains(tee_participant));
    }

    // Additional verification: confirm that non-participants were actually removed
    let initial_total_tee_participants = initial_accounts.len() + stale_accounts.len();
    let cleaned_up_count = initial_total_tee_participants - tee_participants_after_cleanup.len();
    let expected_cleanup_count = initial_total_tee_participants - new_participant_accounts.len();

    assert_eq!(cleaned_up_count, expected_cleanup_count);

    Ok(())
}
