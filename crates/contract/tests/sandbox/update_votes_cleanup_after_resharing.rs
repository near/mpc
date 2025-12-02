use anyhow::Result;
use assert_matches::assert_matches;
use contract_interface::types as dtos;
use serde_json::json;
use utilities::AccountIdExtV1;

use crate::sandbox::common::{
    assert_running_return_participants, assert_running_return_threshold,
    execute_async_transactions, init_env, CURRENT_CONTRACT_DEPLOY_DEPOSIT,
    GAS_FOR_VOTE_NEW_PARAMETERS, PARTICIPANT_LEN,
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
/// Measures gas usage for cleanup methods with maximum number of votes to clean up.
#[tokio::test]
async fn update_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // Use 30 participants to maximize cleanup work while staying within gas limits
    const TEST_PARTICIPANT_LEN: usize = 30;

    // given: a running contract with TEST_PARTICIPANT_LEN participants
    let (_, contract, env_accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], TEST_PARTICIPANT_LEN).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    println!(
        "\n=== Initial Setup ===\nParticipants: {}, Threshold: {}",
        initial_participants.len(),
        threshold.value()
    );

    // Propose update and have participants vote - maximize votes from those who will be removed
    let propose_result = env_accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(ProposeUpdateArgs {
            code: Some(vec![1u8; 1000]),
            config: None,
        })
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let update_id: UpdateId = propose_result.json()?;
    println!("Update ID: {:?}", update_id);

    // Have all participants from threshold onwards vote (these will be removed during resharing)
    let voters_to_be_removed = TEST_PARTICIPANT_LEN - threshold.value() as usize;

    println!(
        "Having {} participants vote (indices {} to {}, these will be removed)",
        voters_to_be_removed,
        threshold.value(),
        TEST_PARTICIPANT_LEN - 1
    );

    execute_async_transactions(
        &env_accounts[threshold.value() as usize..],
        &contract,
        "vote_update",
        &json!({"id": update_id}),
        near_workspaces::types::Gas::from_tgas(300),
    )
    .await?;

    let proposals_before: dtos::ProposedUpdates =
        contract.view("proposed_updates").await?.json()?;

    println!(
        "Votes before resharing: {}",
        proposals_before.0[0].votes.len()
    );
    assert_eq!(proposals_before.0[0].votes.len(), voters_to_be_removed);

    // when: resharing with only threshold participants (removing all voters)
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants()
        .iter()
        .take(threshold.value() as usize)
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
        "\n=== Resharing ===\nNew participants: {} (keeping first {})",
        new_participants.len(),
        threshold.value()
    );
    println!("Votes to clean up: {}", voters_to_be_removed);

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
    for _ in 0..10 {
        let current_state: ProtocolContractState = contract.view("state").await?.json()?;
        if matches!(current_state, ProtocolContractState::Running(_)) {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // then: measure gas usage by calling cleanup methods directly
    println!("\n=== Gas Measurement ===");

    let cleanup_result = contract
        .call("remove_non_participant_update_votes")
        .gas(near_workspaces::types::Gas::from_tgas(10))
        .transact()
        .await?;

    println!(
        "remove_non_participant_update_votes ({} votes): {:.3} Tgas",
        voters_to_be_removed,
        cleanup_result.total_gas_burnt.as_gas() as f64 / 1e12
    );

    let cleanup_result = contract
        .call("clean_tee_status")
        .gas(near_workspaces::types::Gas::from_tgas(10))
        .transact()
        .await?;

    println!(
        "clean_tee_status ({} nodes): {:.3} Tgas",
        voters_to_be_removed,
        cleanup_result.total_gas_burnt.as_gas() as f64 / 1e12
    );

    // Verify cleanup worked
    let proposals_after: dtos::ProposedUpdates = contract.view("proposed_updates").await?.json()?;
    assert_eq!(proposals_after.0[0].votes.len(), 0);

    println!(
        "✓ All {} non-participant votes removed\n",
        voters_to_be_removed
    );

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
