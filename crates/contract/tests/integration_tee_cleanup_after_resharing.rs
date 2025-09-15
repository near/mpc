pub mod common;
use anyhow::Result;
use attestation::attestation::{Attestation, MockAttestation};
use serde_json::json;
use std::collections::BTreeSet;

use common::{
    check_call_success, gen_accounts, get_tee_accounts, init_env_secp256k1, submit_participant_info,
};
use mpc_contract::primitives::test_utils::bogus_ed25519_near_public_key;
use mpc_contract::{
    primitives::{
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
    tee::tee_state::NodeUid,
};

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

    // extract initial participants:
    // Get current state to extract participant info
    let state: ProtocolContractState = contract.view("state").await?.json()?;
    let running_state = match state {
        ProtocolContractState::Running(running_state) => running_state,
        _ => panic!("Contract should be in running state initially"),
    };

    // Get current participants to construct proper ThresholdParameters
    let init_participants = running_state.parameters.participants().clone();

    // Set up TEE attestations for all initial participants
    let mut expected_initial_tee_participants = BTreeSet::new();
    for account in &initial_accounts {
        let attestation = Attestation::Mock(MockAttestation::Valid); // todo #1109, add TLS key.
        let tls_p2p_key = init_participants
            .info(account.id())
            .unwrap()
            .sign_pk
            .clone();
        let submission_result =
            submit_participant_info(account, &contract, &attestation, &tls_p2p_key).await?;
        assert!(submission_result);
        expected_initial_tee_participants.insert(NodeUid {
            account_id: account.id().clone(),
            tls_public_key: tls_p2p_key,
        });
    }

    // Verify TEE participants were added
    let initial_tee_participants: BTreeSet<_> = get_tee_accounts(&contract)
        .await
        .unwrap()
        .into_iter()
        .collect();

    assert_eq!(initial_tee_participants, expected_initial_tee_participants);

    // Create additional accounts to simulate stale participants
    let (non_participants, _) = gen_accounts(&worker, 2).await;

    let mut expected_init_and_non_participants = initial_tee_participants.clone();
    // Add stale participants to TEE state
    for non_participant in &non_participants {
        let attestation = Attestation::Mock(MockAttestation::Valid); // todo #1109, add TLS key.
        let random_tls_key = bogus_ed25519_near_public_key();
        let submission_result =
            submit_participant_info(non_participant, &contract, &attestation, &random_tls_key)
                .await?;
        assert!(submission_result);
        expected_init_and_non_participants.insert(NodeUid {
            account_id: non_participant.id().clone(),
            tls_public_key: random_tls_key,
        });
    }

    let initial_and_non_participants: BTreeSet<_> = get_tee_accounts(&contract)
        .await
        .unwrap()
        .into_iter()
        .collect();

    assert_eq!(
        initial_and_non_participants,
        expected_init_and_non_participants
    );

    // Create new participants list with first 2 participants
    let mut new_participants = Participants::new();
    let mut expected_tee_post_resharing = BTreeSet::new();
    for (account_id, _participant_id, participant_info) in
        init_participants.participants().iter().take(2)
    {
        new_participants
            .insert(account_id.clone(), participant_info.clone())
            .expect("Failed to insert participant");
        expected_tee_post_resharing.insert(NodeUid {
            account_id: account_id.clone(),
            tls_public_key: participant_info.sign_pk.clone(),
        });
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
    let final_participants: BTreeSet<NodeUid> = running_state
        .parameters
        .participants()
        .participants()
        .iter()
        .map(|(account_id, _, p_info)| NodeUid {
            account_id: account_id.clone(),
            tls_public_key: p_info.sign_pk.clone(),
        })
        .collect();

    // Verify only the new participants remain
    assert_eq!(final_participants, expected_tee_post_resharing);

    // Verify TEE participants are properly cleaned up
    let tee_participants_after_cleanup: BTreeSet<NodeUid> = get_tee_accounts(&contract)
        .await
        .unwrap()
        .into_iter()
        .collect();

    // Verify that the remaining TEE participants match exactly the new contract participants
    assert_eq!(tee_participants_after_cleanup, expected_tee_post_resharing);

    Ok(())
}
