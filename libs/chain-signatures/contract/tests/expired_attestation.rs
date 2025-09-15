pub mod common;

use anyhow::Result;
use attestation::attestation::{Attestation, MockAttestation};
use common::{get_tee_accounts, init_env_secp256k1, submit_participant_info};
use mpc_contract::state::ProtocolContractState;
use std::time::{SystemTime, UNIX_EPOCH};
use test_utils::attestation::p2p_tls_key;

/// **Participant kickout after expiration** - Tests the complete expired attestation removal flow.
/// This test demonstrates the full kickout mechanism for nodes with expired attestations:
/// 1. Submit valid attestations for 2 participants and an expiring attestation for 1 participant
/// 2. Wait for the attestation to expire based on its timestamp
/// 3. Call verify_tee() which validates all participant attestations against current time
/// 4. verify_tee() returns false when expired attestations are detected
/// 5. Contract automatically transitions from Running to Resharing state
/// 6. Resharing state preserves all participants during transition
/// 7. Valid participants vote for resharing completion for all domains (0, 2, 4)
/// 8. Multi-domain resharing protocol generates new key shares among valid participants only
/// 9. Contract transitions back to Running state with new participant set (expired participant filtered out)
/// 10. Verify TEE state cleanup - expired participant is removed from TEE accounts
#[tokio::test]
async fn test_participant_kickout_after_expiration() -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(3).await;
    let tls_key = p2p_tls_key();

    // Setup: Give first two participants valid non-expiring attestations
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    for account in &accounts[0..2] {
        let submission_success =
            submit_participant_info(account, &contract, &valid_attestation, &tls_key).await?;
        assert!(submission_success);
    }

    // Time in seconds to wait before an attestation expires
    const ATTESTATION_EXPIRY_SECONDS: u64 = 2;

    // Setup: Give third participant an attestation that expires very soon
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let short_expiry = current_time + ATTESTATION_EXPIRY_SECONDS;

    let soon_expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_time_stamp_seconds: Some(short_expiry),
    });

    let submission_success = submit_participant_info(
        &accounts[2],
        &contract,
        &soon_expiring_attestation,
        &tls_key,
    )
    .await?;
    assert!(submission_success);

    // Verify initial state: should have 3 TEE participants
    let initial_tee_accounts = get_tee_accounts(&contract).await?;
    assert_eq!(initial_tee_accounts.len(), 3);

    let initial_participants = get_participant_count(&contract).await?;
    assert_eq!(initial_participants, 3);

    // Wait for the attestation to expire
    const WAIT_FOR_EXPIRY_SECONDS: u64 = ATTESTATION_EXPIRY_SECONDS + 1;
    std::thread::sleep(std::time::Duration::from_secs(WAIT_FOR_EXPIRY_SECONDS));

    // Call verify_tee() - this should now detect the expired attestation and filter out the participant
    let verify_result: bool = contract
        .call("verify_tee")
        .max_gas()
        .transact()
        .await?
        .json()?;

    // Check the state after verify_tee
    let state = contract.call("state").max_gas().transact().await?;
    let contract_state: ProtocolContractState = state.json()?;

    // The contract must be in Resharing state after expired attestation is detected
    let resharing = match contract_state {
        ProtocolContractState::Resharing(resharing) => resharing,
        _ => panic!(
            "Expected contract to be in Resharing state after expired attestation detected, but got: {:?}",
            std::mem::discriminant(&contract_state)
        ),
    };

    // Check the participant count in the resharing state
    let resharing_participants = resharing
        .previous_running_state
        .parameters
        .participants()
        .len();

    // The resharing state contains the previous running state, which still has all participants
    // The actual filtering happens during the resharing process, not immediately when detected
    assert_eq!(
        resharing_participants, initial_participants,
        "Resharing state should preserve the previous running state with all participants ({})",
        initial_participants
    );

    // The key indicator that the expired attestation was detected is:
    // 1. verify_tee returned false (indicating validation failure)
    // 2. Contract moved to Resharing state (triggered by the validation failure)
    assert!(
        !verify_result,
        "verify_tee should return false when expired attestations are detected"
    );

    // Now test steps 3-4: Complete the resharing process to see actual participant removal

    // Step 3a: Start the resharing instance (required before voting)
    // The resharing state exists but the protocol instance needs to be started
    let key_event_id = serde_json::json!({
        "epoch_id": 6,
        "domain_id": 0,
        "attempt_id": 0
    });

    let _start_reshare_result = accounts[0]
        .call(contract.id(), "start_reshare_instance")
        .args_json(serde_json::json!({ "key_event_id": key_event_id }))
        .max_gas()
        .transact()
        .await?;

    // Step 3b: Complete the resharing process by having valid participants vote
    // We'll have the valid participants (those without expired attestations) vote
    for account in &accounts[0..2] {
        let _vote_result = account
            .call(contract.id(), "vote_reshared")
            .args_json(serde_json::json!({ "key_event_id": key_event_id }))
            .max_gas()
            .transact()
            .await?;
    }

    // Give the contract some time to process the votes and complete the resharing
    std::thread::sleep(std::time::Duration::from_secs(1));

    // The resharing process is multi-domain. Complete resharing for remaining domains.
    for domain_id in [2, 4] {
        let key_event_id = serde_json::json!({
            "epoch_id": 6,
            "domain_id": domain_id,
            "attempt_id": 0
        });

        let _start_reshare_result = accounts[0]
            .call(contract.id(), "start_reshare_instance")
            .args_json(serde_json::json!({ "key_event_id": key_event_id }))
            .max_gas()
            .transact()
            .await?;

        // Vote for resharing with valid participants only
        for account in &accounts[0..2] {
            let _vote_result = account
                .call(contract.id(), "vote_reshared")
                .args_json(serde_json::json!({ "key_event_id": key_event_id }))
                .max_gas()
                .transact()
                .await?;
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Give the contract some time to process all domain resharing and transition back to Running
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Check if resharing completed and state transitioned back to Running
    let state_after_voting = contract.call("state").max_gas().transact().await?;
    let contract_state_after_voting: ProtocolContractState = state_after_voting.json()?;

    match contract_state_after_voting {
        ProtocolContractState::Running(running_state) => {
            let _final_participants = running_state.parameters.participants().len();

            // Step 4: Verify actual cleanup happened
            // The cleanup should have been triggered by vote_reshared via clean_tee_status

            // Check TEE accounts after cleanup - this should show the actual removal
            let final_tee_accounts = get_tee_accounts(&contract).await?;

            // The key validation: TEE accounts should now match the active participants
            // (expired attestation participant should be removed from TEE state)
            assert!(
                final_tee_accounts.len() < initial_tee_accounts.len(),
                "Participant with expired attestation should be removed from TEE state. Initial: {}, Final: {}",
                initial_tee_accounts.len(),
                final_tee_accounts.len()
            );
        }
        _ => {
            panic!(
                "Contract should have transitioned back to Running state after resharing completion"
            );
        }
    }

    Ok(())
}

// Helper function to get participant count
async fn get_participant_count(contract: &near_workspaces::Contract) -> Result<usize> {
    let contract_state = contract.call("state").max_gas().transact().await?;
    let contract_state: ProtocolContractState = contract_state.json()?;
    match contract_state {
        ProtocolContractState::Running(running) => Ok(running.parameters.participants().len()),
        _ => panic!("Expected contract to be in Running state when getting participant count"),
    }
}
