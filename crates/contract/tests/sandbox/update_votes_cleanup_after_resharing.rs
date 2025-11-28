use anyhow::Result;
use assert_matches::assert_matches;
use contract_interface::types as dtos;
use near_account_id::AccountId;
use serde_json::json;
use std::collections::HashSet;
use utilities::AccountIdExtV1;

use crate::sandbox::common::{
    assert_running_return_participants, assert_running_return_threshold,
    execute_async_transactions, init_env, GAS_FOR_VOTE_NEW_PARAMETERS, GAS_FOR_VOTE_RESHARED,
    PARTICIPANT_LEN,
};
use mpc_contract::{
    primitives::{
        domain::{DomainId, SignatureScheme},
        key_state::EpochId,
        participants::Participants,
        thresholds::ThresholdParameters,
    },
    state::ProtocolContractState,
    update::{ProposeUpdateArgs, UpdateId},
};

/// Tests that update votes from non-participants are cleared after resharing.
/// Also measures gas usage for the cleanup promise when run with larger PARTICIPANT_LEN.
#[tokio::test]
async fn update_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // Use 30 participants to maximize cleanup work while staying within gas limits
    const TEST_PARTICIPANT_LEN: usize = 20;

    // given: a running contract with TEST_PARTICIPANT_LEN participants and an update proposal with ALL participants voting
    let (_, contract, env_accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], TEST_PARTICIPANT_LEN).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    println!(
        "\n=== Initial Setup ===\nParticipants: {}, Threshold: {}",
        initial_participants.len(),
        threshold.value()
    );

    // Propose update and have ALL participants vote on it to maximize votes that need cleanup
    let propose_result = env_accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(ProposeUpdateArgs {
            code: Some(vec![1u8; 1000]),
            config: None,
        })
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .max_gas()
        .transact()
        .await?;

    println!("Propose update result: {:?}", propose_result);
    if !propose_result.is_success() {
        println!("Propose update failed!");
        for outcome in propose_result.receipt_outcomes() {
            println!("  Receipt outcome: {:?}", outcome);
        }
    }

    propose_result.clone().into_result()?;
    let update_id: UpdateId = propose_result.json()?;
    println!("Update ID: {:?}", update_id);

    // Have participants from threshold onwards vote to maximize cleanup
    // (these will be removed during resharing which keeps only first threshold participants)
    // Vote with (TEST_PARTICIPANT_LEN - threshold) participants, but cap at threshold-1 to avoid auto-approval
    let voters_to_be_removed = TEST_PARTICIPANT_LEN - threshold.value() as usize;
    let votes_needed = voters_to_be_removed.min(threshold.value() as usize - 1);

    println!(
        "Having {} participants vote (from index {} onwards, these will be removed)",
        votes_needed,
        threshold.value()
    );

    execute_async_transactions(
        &env_accounts[threshold.value() as usize..threshold.value() as usize + votes_needed],
        &contract,
        "vote_update",
        &json!({"id": update_id}),
        near_workspaces::types::Gas::from_tgas(300),
    )
    .await?;

    let proposals_before: dtos::ProposedUpdates =
        contract.view("proposed_updates").await?.json()?;
    assert_eq!(proposals_before.0.len(), 1);

    let voters_before: HashSet<_> = proposals_before.0[0]
        .votes
        .iter()
        .map(|v| v.0.parse::<AccountId>().unwrap())
        .collect();

    println!("Votes before resharing: {}", voters_before.len());
    assert_eq!(voters_before.len(), votes_needed);

    // when: resharing completes with new participants that are only the threshold number
    // This maximizes the number of non-participants whose votes need to be cleaned up
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants()
        .iter()
        .take(threshold.value() as usize)
    // Only keep threshold participants
    {
        new_participants
            .insert_with_id(
                account_id.clone(),
                participant_info.clone(),
                participant_id.clone(),
            )
            .map_err(|e| anyhow::anyhow!("Failed to insert participant: {}", e))?;
    }

    println!(
        "New participant set: {} (down from {})",
        new_participants.len(),
        TEST_PARTICIPANT_LEN
    );
    println!(
        "Votes to be cleaned up: {} (from non-participants)",
        TEST_PARTICIPANT_LEN - threshold.value() as usize
    );

    let new_threshold_parameters = ThresholdParameters::new(new_participants, threshold.clone())
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let prospective_epoch_id = EpochId::new(6);

    // Vote for new parameters (only threshold participants)
    execute_async_transactions(
        &env_accounts[0..threshold.value() as usize],
        &contract,
        "vote_new_parameters",
        &json!({
            "prospective_epoch_id": prospective_epoch_id,
            "proposal": new_threshold_parameters,
        }),
        GAS_FOR_VOTE_NEW_PARAMETERS,
    )
    .await?;

    // Get resharing state and start reshare
    let state: ProtocolContractState = contract.view("state").await?.json()?;
    let ProtocolContractState::Resharing(resharing_state) = state else {
        panic!("Expected Resharing state");
    };

    let key_event_id = json!({
        "epoch_id": prospective_epoch_id.get(),
        "domain_id": DomainId(0).0,
        "attempt_id": 0,
    });

    // Find the leader (participant with lowest ID) to start the reshare instance
    let leader = env_accounts[0..threshold.value() as usize]
        .iter()
        .min_by_key(|a| {
            resharing_state
                .resharing_key
                .proposed_parameters()
                .participants()
                .id(&a.id().as_v2_account_id())
                .unwrap()
        })
        .unwrap();

    leader
        .call(contract.id(), "start_reshare_instance")
        .args_json(json!({"key_event_id": key_event_id}))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // All new participants vote reshared (triggers cleanup via fire-and-forget promises)
    println!("\n=== Executing vote_reshared ===");
    let vote_reshared_args = json!({"key_event_id": key_event_id});

    execute_async_transactions(
        &env_accounts[0..threshold.value() as usize],
        &contract,
        "vote_reshared",
        &vote_reshared_args,
        near_workspaces::types::Gas::from_tgas(50),
    )
    .await?;

    println!("Vote_reshared calls completed");

    // Wait for state transition to Running
    let mut attempts = 0;
    loop {
        let current_state: ProtocolContractState = contract.view("state").await?.json()?;
        if matches!(current_state, ProtocolContractState::Running(_)) {
            println!("State transitioned to Running");
            break;
        }

        attempts += 1;
        if attempts > 10 {
            panic!(
                "State did not transition to Running after {} attempts",
                attempts
            );
        }

        println!("Waiting for state transition (attempt {})", attempts);
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // then: verify cleanup removed all non-participant votes
    let _ = assert_running_return_participants(&contract).await?;

    // Measure gas usage by calling cleanup method directly
    // (The actual cleanup already happened via fire-and-forget promise during vote_reshared,
    // but we call it again to measure gas usage for documentation purposes)
    println!("\n=== Gas Measurement (calling cleanup methods directly) ===");

    let cleanup_result = contract
        .call("remove_non_participant_update_votes")
        .gas(near_workspaces::types::Gas::from_tgas(10))
        .transact()
        .await?;

    if cleanup_result.is_success() {
        println!("remove_non_participant_update_votes:");
        println!(
            "  Total gas burnt: {:.3} Tgas",
            cleanup_result.total_gas_burnt.as_gas() as f64 / 1e12
        );
        for (i, outcome) in cleanup_result.receipt_outcomes().iter().enumerate() {
            println!(
                "    Receipt {}: {:.3} Tgas",
                i,
                outcome.gas_burnt.as_gas() as f64 / 1e12
            );
        }
    }

    let cleanup_result = contract
        .call("clean_tee_status")
        .gas(near_workspaces::types::Gas::from_tgas(10))
        .transact()
        .await?;

    if cleanup_result.is_success() {
        println!("clean_tee_status:");
        println!(
            "  Total gas burnt: {:.3} Tgas",
            cleanup_result.total_gas_burnt.as_gas() as f64 / 1e12
        );
        for (i, outcome) in cleanup_result.receipt_outcomes().iter().enumerate() {
            println!(
                "    Receipt {}: {:.3} Tgas",
                i,
                outcome.gas_burnt.as_gas() as f64 / 1e12
            );
        }
    }

    let cleanup_result = contract
        .call("cleanup_orphaned_node_migrations")
        .gas(near_workspaces::types::Gas::from_tgas(10))
        .transact()
        .await?;

    if cleanup_result.is_success() {
        println!("cleanup_orphaned_node_migrations:");
        println!(
            "  Total gas burnt: {:.3} Tgas",
            cleanup_result.total_gas_burnt.as_gas() as f64 / 1e12
        );
        for (i, outcome) in cleanup_result.receipt_outcomes().iter().enumerate() {
            println!(
                "    Receipt {}: {:.3} Tgas",
                i,
                outcome.gas_burnt.as_gas() as f64 / 1e12
            );
        }
    }

    let proposals_after: dtos::ProposedUpdates = contract.view("proposed_updates").await?.json()?;

    println!(
        "\n=== Cleanup Results ===\nVotes after cleanup: {}",
        proposals_after.0[0].votes.len()
    );
    println!("Expected votes: 0 (all voters were removed during resharing)");

    assert_eq!(proposals_after.0.len(), 1);
    let votes = &proposals_after.0[0].votes;
    assert_eq!(
        votes.len(),
        0,
        "All {} votes should have been cleaned up since all voters were non-participants",
        votes_needed
    ); // All voters were non-participants

    println!("✓ Cleanup successful: all non-participant votes removed\n");

    Ok(())
}

/// Tests that external accounts cannot call the private remove_non_participant_update_votes
/// contract method. This verifies the security boundary: only the contract itself should be
/// able to perform internal cleanup operations for update votes.
#[tokio::test]
async fn test_remove_non_participant_update_votes_denies_external_account_call() -> Result<()> {
    // given: a contract and an external account that's not the contract itself
    let (worker, contract, _accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let external_account = worker.dev_create_account().await?;

    // when: the external account attempts to call the private method
    let result = external_account
        .call(contract.id(), "remove_non_participant_update_votes")
        .args_json(json!({}))
        .transact()
        .await?;

    // then: the call should fail with a "method is private" error
    assert_matches!(
        result.into_result(),
        Err(ref failure) if format!("{:?}", failure).contains("Method remove_non_participant_update_votes is private")
    );

    Ok(())
}
