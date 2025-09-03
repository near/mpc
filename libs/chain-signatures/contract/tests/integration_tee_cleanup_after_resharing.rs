pub mod common;

use anyhow::Result;
use attestation::attestation::{Attestation, LocalAttestation};
use near_workspaces::AccountId;
use serde_json::json;
use std::collections::HashSet;

use common::{
    check_call_success, gen_accounts, get_tee_accounts, init_env_secp256k1, submit_participant_info,
};
use mpc_contract::{
    primitives::{
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
};
use test_utils::attestation::p2p_tls_key;

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
    let attestation = Attestation::Local(LocalAttestation::Valid);

    for account in &initial_accounts {
        let submission_result =
            submit_participant_info(account, &contract, &attestation, &tls_key).await?;
        assert!(submission_result);
    }

    // Verify TEE participants were added
    let initial_tee_participants = get_tee_accounts(&contract).await?;
    assert_eq!(initial_tee_participants.len(), initial_accounts.len());

    // Create additional accounts to simulate stale participants
    let (stale_accounts, _) = gen_accounts(&worker, 2).await;

    // Add stale participants to TEE state
    for stale_account in &stale_accounts {
        let submission_result =
            submit_participant_info(stale_account, &contract, &attestation, &tls_key).await?;
        assert!(submission_result);
    }

    // Verify all participants are in TEE state (initial + stale)
    let all_tee_participants = get_tee_accounts(&contract).await?;
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

    // Create new participants list with first 2 participants
    let mut new_participants = Participants::new();
    for (account_id, _participant_id, participant_info) in
        current_participants.participants().iter().take(2)
    {
        new_participants
            .insert(account_id.clone(), participant_info.clone())
            .expect("Failed to insert participant");
    }

    // Create proper ThresholdParameters
    let new_threshold_parameters =
        ThresholdParameters::new(new_participants, Threshold::new(2)).unwrap();

    // Use hardcoded prospective epoch ID for test simplicity
    // Based on the test setup, the contract starts with epoch 5, so next epoch is 6
    let prospective_epoch_id = 6;

    // Vote for new parameters with threshold participants (2 out of 3)
    // The transition to resharing should happen after 2 votes when threshold is reached
    for account in initial_accounts.iter().take(2) {
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

    // Wait for threshold participants to vote for resharing (2 out of 3)
    // The transition should happen after 2 votes when threshold is reached
    for account in initial_accounts.iter().take(2) {
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
    let final_participants: HashSet<AccountId> = running_state
        .parameters
        .participants()
        .participants()
        .iter()
        .map(|(account_id, _, _)| account_id.clone())
        .collect();

    // Create expected participants set
    let expected_participants: HashSet<AccountId> = new_participant_accounts
        .iter()
        .map(|acc| acc.id().clone())
        .collect();

    // Verify only the new participants remain
    assert_eq!(final_participants, expected_participants);

    // Verify TEE participants are properly cleaned up
    let tee_participants_after_cleanup: HashSet<AccountId> = contract
        .call("get_tee_accounts")
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?
        .json::<Vec<AccountId>>()?
        .into_iter()
        .collect();

    // Verify that the remaining TEE participants match exactly the new contract participants
    assert_eq!(tee_participants_after_cleanup, expected_participants);

    Ok(())
}
