use anyhow::Result;
use contract_interface::types as dtos;
use near_account_id::AccountId;
use serde_json::json;
use std::collections::HashSet;
use utilities::AccountIdExtV1;

use crate::sandbox::common::{
    assert_running_return_participants, assert_running_return_threshold,
    execute_async_transactions, init_env, GAS_FOR_VOTE_RESHARED, PARTICIPANT_LEN,
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
#[tokio::test]
async fn test_update_votes_cleared_after_resharing() -> Result<()> {
    let (_, contract, env_accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    // Propose update and have first 2 participants vote on it
    let update_id: UpdateId = env_accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(ProposeUpdateArgs {
            code: Some(vec![1u8; 1000]),
            config: None,
        })
        .deposit(near_workspaces::types::NearToken::from_near(1))
        .max_gas()
        .transact()
        .await?
        .json()?;

    for account in &env_accounts[0..2] {
        account
            .call(contract.id(), "vote_update")
            .args_json(json!({"id": update_id}))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
    }

    let proposals_before: dtos::ProposedUpdates =
        contract.view("proposed_updates").await?.json()?;
    assert_eq!(proposals_before.0.len(), 1);

    let voters_before: HashSet<_> = proposals_before.0[0]
        .votes
        .iter()
        .map(|v| v.0.parse::<AccountId>().unwrap())
        .collect();
    assert_eq!(
        voters_before,
        HashSet::from([
            env_accounts[0].id().as_v2_account_id(),
            env_accounts[1].id().as_v2_account_id()
        ])
    );

    // Reshare with threshold participants, excluding participant 0 who voted
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants()
        .iter()
        .skip(1) // Skip participant 0, so participant 1-6 are included
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

    let new_threshold_parameters = ThresholdParameters::new(new_participants, threshold.clone())
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let prospective_epoch_id = EpochId::new(6);

    // Vote for new parameters (skip participant 0, use participants 1-6)
    for account in &env_accounts[1..threshold.value() as usize + 1] {
        account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": prospective_epoch_id,
                "proposal": new_threshold_parameters,
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
    }

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
    env_accounts[1..threshold.value() as usize + 1]
        .iter()
        .min_by_key(|a| {
            resharing_state
                .resharing_key
                .proposed_parameters()
                .participants()
                .id(&a.id().as_v2_account_id())
                .unwrap()
        })
        .unwrap()
        .call(contract.id(), "start_reshare_instance")
        .args_json(json!({"key_event_id": key_event_id}))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // All new participants vote reshared (triggers cleanup via promise on state transition)
    let vote_reshared_args = json!({"key_event_id": key_event_id});
    execute_async_transactions(
        &env_accounts[1..threshold.value() as usize + 1],
        &contract,
        "vote_reshared",
        &vote_reshared_args,
        GAS_FOR_VOTE_RESHARED,
    )
    .await?;

    // Verify votes cleaned up - only current participants should have votes
    let final_participants = assert_running_return_participants(&contract).await?;
    let proposals_after: dtos::ProposedUpdates = contract.view("proposed_updates").await?.json()?;

    assert_eq!(proposals_after.0.len(), 1);
    let votes = &proposals_after.0[0].votes;
    assert_eq!(votes.len(), 1); // Only participant 1's vote remains (participant 0 was excluded)
    let voter_id: AccountId = votes[0].0.parse().unwrap();
    assert!(final_participants.is_participant(&voter_id));

    Ok(())
}
