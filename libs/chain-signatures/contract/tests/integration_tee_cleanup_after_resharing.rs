pub mod common;

use near_workspaces::{Account, AccountId, Contract};
use serde_json::json;

use attestation::attestation::Attestation;
use common::{check_call_success, gen_accounts, init_env_secp256k1};
use mpc_contract::primitives::participants::Participants;
use mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters};
use mpc_contract::state::ProtocolContractState;
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::PublicKey;
use test_utils::attestation::{mock_local_attestation, p2p_tls_key};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

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

/// Helper function to submit participant info with TEE attestation
async fn submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &PublicKey,
) -> Result<bool> {
    let result = account
        .call(contract.id(), "submit_participant_info")
        .args_borsh((attestation.clone(), tls_key.clone()))
        .max_gas()
        .transact()
        .await?;

    Ok(result.is_success())
}

/// Helper function to get TEE participants
async fn get_tee_participants(contract: &Contract) -> Result<Vec<AccountId>> {
    Ok(contract
        .call("get_tee_participants")
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?
        .json()?)
}

/// Integration test that validates the complete E2E flow of TEE cleanup after resharing.
///
/// This test:
/// 1. Sets up an initial participant set with TEE attestations
/// 2. Adds additional TEE participants (simulating stale data from previous resharing)
/// 3. Initiates a new resharing with a subset of the original participants
/// 4. Completes the resharing process by voting
/// 5. Verifies that vote_reshared triggered cleanup of stale TEE attestations
/// 6. Confirms only the new participant set remains in TEE state
#[tokio::test]
async fn test_tee_cleanup_after_full_resharing_flow() -> Result<()> {
    // Initialize environment with 3 participants (that's the default)
    const INITIAL_PARTICIPANTS: usize = 3;
    let (worker, contract, initial_accounts, _) = init_env_secp256k1(1).await;

    // Verify we have the expected number of participants
    assert_eq!(
        initial_accounts.len(),
        INITIAL_PARTICIPANTS,
        "Should have {} initial participants",
        INITIAL_PARTICIPANTS
    );

    // Set up approved MPC hash for TEE operations
    setup_contract_with_approved_hash(&contract, &initial_accounts).await?;

    // Set up TEE attestations for all initial participants
    let tls_key = p2p_tls_key();
    let attestation = mock_local_attestation(true);

    for account in &initial_accounts {
        let success = submit_participant_info(account, &contract, &attestation, &tls_key).await?;
        println!("TEE submission for {}: {}", account.id(), success);
        assert!(
            success,
            "TEE submission should succeed for participant {}",
            account.id()
        );
    }

    // Verify TEE participants were added
    let initial_tee_participants = get_tee_participants(&contract).await?;
    println!("Initial TEE participants: {:?}", initial_tee_participants);
    assert_eq!(
        initial_tee_participants.len(),
        INITIAL_PARTICIPANTS,
        "Should have {} initial TEE participants",
        INITIAL_PARTICIPANTS
    );

    // Create additional accounts to simulate stale participants from previous resharing
    let (stale_accounts, _) = gen_accounts(&worker, 2).await;

    // Add stale participants to TEE state
    for stale_account in &stale_accounts {
        let success =
            submit_participant_info(stale_account, &contract, &attestation, &tls_key).await?;
        println!(
            "Added stale TEE participant {}: {}",
            stale_account.id(),
            success
        );
        assert!(
            success,
            "TEE submission should succeed for stale participant {}",
            stale_account.id()
        );
    }

    // Verify all participants are in TEE state (initial + stale)
    let all_tee_participants = get_tee_participants(&contract).await?;
    println!(
        "Total TEE participants before resharing: {} (expected: {})",
        all_tee_participants.len(),
        INITIAL_PARTICIPANTS + stale_accounts.len()
    );
    println!("TEE participants: {:?}", all_tee_participants);
    assert_eq!(
        all_tee_participants.len(),
        INITIAL_PARTICIPANTS + stale_accounts.len(),
        "Should have initial + stale participants in TEE state"
    );

    // Get current state to calculate prospective epoch ID
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
    let new_threshold_parameters = ThresholdParameters::new(new_participants, Threshold::new(2))
        .expect("Failed to create ThresholdParameters");

    println!("New threshold parameters: {:?}", new_threshold_parameters);

    // Calculate prospective epoch ID based on contract's logic
    let prospective_epoch_id = match running_state.previously_cancelled_resharing_epoch_id {
        Some(cancelled_epoch_id) => cancelled_epoch_id.next(),
        None => running_state.keyset.epoch_id.next(),
    };

    println!(
        "Current epoch: {}, Prospective epoch: {}",
        running_state.keyset.epoch_id.get(),
        prospective_epoch_id.get()
    );

    // Vote one by one and check the state after each vote
    for (i, account) in initial_accounts.iter().enumerate() {
        println!(
            "Voting with account {} (vote {} of {})",
            account.id(),
            i + 1,
            initial_accounts.len()
        );

        // Check contract state before this vote
        let pre_vote_state: ProtocolContractState = contract.view("state").await?.json()?;
        if let ProtocolContractState::Running(running_state) = &pre_vote_state {
            let expected_epoch = match running_state.previously_cancelled_resharing_epoch_id {
                Some(cancelled_epoch_id) => cancelled_epoch_id.next(),
                None => running_state.keyset.epoch_id.next(),
            };
            println!(
                "Before vote {}: Current epoch: {}, Expected epoch: {}, Previously cancelled: {:?}",
                i + 1,
                running_state.keyset.epoch_id.get(),
                expected_epoch.get(),
                running_state
                    .previously_cancelled_resharing_epoch_id
                    .map(|e| e.get())
            );
        }

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
            ProtocolContractState::Running(running_state) => {
                println!(
                    "After vote {}: State is Running, epoch: {}, Previously cancelled: {:?}",
                    i + 1,
                    running_state.keyset.epoch_id.get(),
                    running_state
                        .previously_cancelled_resharing_epoch_id
                        .map(|e| e.get())
                );
            }
            ProtocolContractState::Resharing(resharing_state) => {
                println!(
                    "After vote {}: State transitioned to Resharing! Prospective epoch: {}",
                    i + 1,
                    resharing_state.prospective_epoch_id().get()
                );
                break; // Stop voting once we're in resharing
            }
            _ => {
                println!(
                    "After vote {}: Unexpected state: {:?}",
                    i + 1,
                    post_vote_state
                );
            }
        }
    }

    // Verify contract is now in resharing state
    let state: ProtocolContractState = contract.view("state").await?.json()?;
    println!("Final state after voting: {:?}", state);

    if let ProtocolContractState::Resharing(resharing_state) = state {
        println!("Contract transitioned to Resharing state successfully!");
        println!("Resharing key event: {:?}", resharing_state.resharing_key);

        // We need to start the reshare instance first
        let key_event_id = json!({
            "epoch_id": resharing_state.prospective_epoch_id().get(),
            "domain_id": 0,
            "attempt_id": 0,
        });

        println!(
            "Starting reshare instance with key_event_id: {:?}",
            key_event_id
        );

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

        println!("Reshare instance started successfully!");

        // Wait for all participants to vote for resharing
        println!("Starting vote_reshared calls...");
        let mut transition_happened = false;
        for (i, account) in initial_accounts.iter().enumerate() {
            println!(
                "vote_reshared call {} of {} from account {}",
                i + 1,
                initial_accounts.len(),
                account.id()
            );

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
                    println!("After vote_reshared {}: Still in Resharing state", i + 1);
                }
                ProtocolContractState::Running(_) => {
                    println!(
                        "After vote_reshared {}: Transitioned back to Running state",
                        i + 1
                    );
                    transition_happened = true;
                    break;
                }
                _ => {
                    println!(
                        "After vote_reshared {}: Unexpected state: {:?}",
                        i + 1,
                        interim_state
                    );
                }
            }
        }

        // Wait for the TEE cleanup promise to execute
        if transition_happened {
            println!("Waiting for TEE cleanup promise to execute...");
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            println!("TEE cleanup promise should have completed");
        }

        // Verify contract is back to running state with new threshold
        let final_state: ProtocolContractState = contract.view("state").await?.json()?;
        if let ProtocolContractState::Running(running_state) = final_state {
            println!("Successfully transitioned back to Running state");
            println!("New threshold: {:?}", running_state.parameters.threshold());
            println!("New epoch: {}", running_state.keyset.epoch_id.get());

            // Get current participants to compare
            let final_participants: Vec<AccountId> = running_state
                .parameters
                .participants()
                .participants()
                .iter()
                .map(|(account_id, _, _)| account_id.clone())
                .collect();
            println!("Final participants: {:?}", final_participants);

            // Verify only the new participants remain
            let expected_participants: Vec<AccountId> = new_participant_accounts
                .iter()
                .map(|acc| acc.id().clone())
                .collect();
            println!("Expected participants: {:?}", expected_participants);

            assert_eq!(
                final_participants.len(),
                new_participant_accounts.len(),
                "Should have {} final participants",
                new_participant_accounts.len()
            );

            for expected_participant in &expected_participants {
                assert!(
                    final_participants.contains(expected_participant),
                    "Final participants should contain {}",
                    expected_participant
                );
            }

            // CRITICAL: Verify TEE participants are properly cleaned up
            let tee_participants_after_cleanup: Vec<AccountId> = contract
                .call("get_tee_participants")
                .args_json(serde_json::json!({}))
                .max_gas()
                .transact()
                .await?
                .json()?;

            println!("=== TEE CLEANUP VERIFICATION ===");
            println!(
                "TEE participants before resharing: {} participants",
                INITIAL_PARTICIPANTS + stale_accounts.len()
            );
            println!("  - Initial participants: {}", INITIAL_PARTICIPANTS);
            println!("  - Stale participants: {}", stale_accounts.len());
            println!(
                "TEE participants after cleanup: {:?}",
                tee_participants_after_cleanup
            );
            println!("Expected after cleanup: Only new participants (non-participants should be cleaned up)");

            // The expected behavior: TEE cleanup should remove non-participants, but keep participants
            let expected_remaining_tee_participants: Vec<AccountId> = new_participant_accounts
                .iter()
                .map(|acc| acc.id().clone())
                .collect();

            println!(
                "Expected remaining TEE participants: {:?}",
                expected_remaining_tee_participants
            );

            // Verify that the remaining TEE participants match exactly the new contract participants
            assert_eq!(
                tee_participants_after_cleanup.len(),
                expected_remaining_tee_participants.len(),
                "TEE cleanup should keep {} participants (the contract participants), but found {}",
                expected_remaining_tee_participants.len(),
                tee_participants_after_cleanup.len()
            );

            for expected_participant in &expected_remaining_tee_participants {
                assert!(
                    tee_participants_after_cleanup.contains(expected_participant),
                    "TEE participants should contain contract participant: {}",
                    expected_participant
                );
            }

            for tee_participant in &tee_participants_after_cleanup {
                assert!(
                    expected_remaining_tee_participants.contains(tee_participant),
                    "TEE participants should only contain contract participants, but found: {}",
                    tee_participant
                );
            }

            println!("✅ TEE cleanup verification PASSED: Non-participants were cleaned up, participants were kept");

            // Additional verification: confirm that non-participants were actually removed
            let initial_total_tee_participants = INITIAL_PARTICIPANTS + stale_accounts.len();
            let cleaned_up_count =
                initial_total_tee_participants - tee_participants_after_cleanup.len();
            let expected_cleanup_count =
                initial_total_tee_participants - new_participant_accounts.len();

            assert_eq!(
                cleaned_up_count, expected_cleanup_count,
                "Expected to clean up {} non-participants, but cleaned up {}",
                expected_cleanup_count, cleaned_up_count
            );

            println!(
                "✅ Cleaned up {} non-participant TEE entries as expected",
                cleaned_up_count
            );

            // VERIFY: Check that resharing completed successfully with correct participants
            println!("✅ Resharing completed successfully!");
            println!(
                "✅ Contract now has {} participants: {:?}",
                final_participants.len(),
                final_participants
            );
            println!("✅ New epoch: {}", running_state.keyset.epoch_id.get());
            println!(
                "✅ New threshold: {:?}",
                running_state.parameters.threshold()
            );
        } else {
            panic!(
                "Expected contract to be in Running state after resharing, but got: {:?}",
                final_state
            );
        }
    } else {
        panic!("Expected contract to be in Resharing state after voting");
    }

    Ok(())
}
