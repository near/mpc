use anyhow::Result;
use contract_interface::types as dtos;
use near_account_id::AccountId;
use near_workspaces::Account;
use serde_json::json;
use sha2::Digest;
use utilities::AccountIdExtV1;

use crate::sandbox::common::{
    assert_running_return_participants, assert_running_return_threshold, do_resharing,
    execute_async_transactions, init_env, CURRENT_CONTRACT_DEPLOY_DEPOSIT, PARTICIPANT_LEN,
};
use mpc_contract::{
    primitives::{
        domain::{DomainId, SignatureScheme},
        key_state::EpochId,
        participants::Participants,
        thresholds::ThresholdParameters,
    },
    update::{ProposeUpdateArgs, UpdateId},
};

/// Tests that update votes from non-participants are cleared after resharing.
#[tokio::test]
async fn update_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // given: a running contract with PARTICIPANT_LEN participants and an update proposal with 2 votes
    let (_, contract, env_accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    // Propose update and have first 2 participants vote on it
    let code = vec![1u8; 1000];
    let update_id: UpdateId = env_accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(ProposeUpdateArgs {
            code: Some(code.clone()),
            config: None,
        })
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await?
        .json()?;

    execute_async_transactions(
        &env_accounts[0..2],
        &contract,
        "vote_update",
        &json!({"id": update_id}),
        near_workspaces::types::Gas::from_tgas(300),
    )
    .await?;

    let proposals_before: dtos::ProposedUpdates =
        contract.view("proposed_updates").await?.json()?;

    assert_expected_proposed_update(&proposals_before, &update_id, &code, &env_accounts[0..2]);

    // when: resharing completes with new participants that exclude participant 0
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

    // when: resharing completes with new participants that exclude participant 0
    do_resharing(
        &env_accounts[1..threshold.value() as usize + 1],
        &contract,
        new_threshold_parameters,
        prospective_epoch_id,
        &[DomainId(0)],
    )
    .await?;

    // then: the cleanup promise removes participant 0's vote from storage
    let final_participants = assert_running_return_participants(&contract).await?;
    let proposals_after: dtos::ProposedUpdates = contract.view("proposed_updates").await?.json()?;

    assert_expected_proposed_update(&proposals_after, &update_id, &code, &env_accounts[1..2]);

    // Verify the remaining voter is still a participant
    let votes = &proposals_after.0[0].votes;
    assert_eq!(votes.len(), 1);
    let voter_id: AccountId = votes[0].0.parse().unwrap();
    assert!(final_participants.is_participant(&voter_id));

    Ok(())
}

pub fn assert_expected_proposed_update(
    actual_proposed_updates: &dtos::ProposedUpdates,
    expected_update_id: &UpdateId,
    expected_update_code: &[u8],
    expected_voter_accounts: &[Account],
) {
    let mut expected_votes: Vec<_> = expected_voter_accounts
        .iter()
        .map(|a| dtos::AccountId(a.id().as_v2_account_id().to_string()))
        .collect();
    expected_votes.sort();

    let expected_update = dtos::Update {
        update_id: **expected_update_id,
        update_hash: dtos::UpdateHash::Code(sha2::Sha256::digest(expected_update_code).into()),
        votes: expected_votes,
    };

    let mut actual_updates = actual_proposed_updates.clone();
    actual_updates.0.iter_mut().for_each(|u| u.votes.sort());

    assert_eq!(actual_updates, dtos::ProposedUpdates(vec![expected_update]));
}
