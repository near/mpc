use crate::sandbox::{
    common::{init_env, SandboxTestSetup},
    utils::{
        consts::{CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_VOTE_UPDATE, PARTICIPANT_LEN},
        mpc_contract::{assert_running_return_participants, assert_running_return_threshold},
        resharing_utils::do_resharing,
        transactions::execute_async_transactions,
    },
};
use anyhow::Result;
use contract_interface::types as dtos;
use mpc_contract::{
    primitives::{
        domain::SignatureScheme, key_state::EpochId, participants::Participants,
        thresholds::ThresholdParameters,
    },
    update::{ProposeUpdateArgs, UpdateId},
};
use near_account_id::AccountId;
use near_workspaces::Account;
use serde_json::json;
use sha2::Digest;
use std::collections::BTreeMap;
use utilities::AccountIdExtV1;

/// Tests that update votes from non-participants are cleared after resharing.
#[tokio::test]
async fn update_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // given: a running contract with PARTICIPANT_LEN participants and an update proposal with 2 votes
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    // Propose update and have first 2 participants vote on it
    let code = vec![1u8; 1000];
    let update_id: UpdateId = mpc_signer_accounts[0]
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
        &mpc_signer_accounts[0..2],
        &contract,
        "vote_update",
        &json!({"id": update_id}),
        GAS_FOR_VOTE_UPDATE,
    )
    .await?;

    let proposals_before: dtos::ProposedUpdates =
        contract.view("proposed_updates").await?.json()?;

    assert_expected_proposed_update(
        &proposals_before,
        &update_id,
        &code,
        &mpc_signer_accounts[0..2],
    );

    // when: resharing completes with new participants that exclude participant 0
    // Reshare with threshold participants, excluding participant 0 who voted
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants()
        .iter()
        .skip(1) // Skip participant 0, so participant 1-6 are included
        .take(usize::try_from(threshold.value()).expect("threshold fits in usize"))
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
        &mpc_signer_accounts
            [1..usize::try_from(threshold.value()).expect("threshold fits in usize") + 1],
        &contract,
        new_threshold_parameters,
        prospective_epoch_id,
    )
    .await?;

    // then: the cleanup promise removes participant 0's vote from storage
    let final_participants = assert_running_return_participants(&contract).await?;
    let proposals_after: dtos::ProposedUpdates = contract.view("proposed_updates").await?.json()?;

    assert_expected_proposed_update(
        &proposals_after,
        &update_id,
        &code,
        &mpc_signer_accounts[1..2],
    );

    // Verify the remaining voter is still a participant
    let votes_for_update: Vec<_> = proposals_after
        .votes
        .iter()
        .filter(|(_, uid)| **uid == *update_id)
        .map(|(account, _)| account)
        .collect();
    assert_eq!(votes_for_update.len(), 1);
    let voter_id: AccountId = votes_for_update[0].0.parse().unwrap();
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

    // Build expected votes map
    let expected_votes_map: BTreeMap<dtos::AccountId, u64> = expected_votes
        .into_iter()
        .map(|account_id| (account_id, **expected_update_id))
        .collect();

    // Build expected updates map
    let mut expected_updates_map = BTreeMap::new();
    expected_updates_map.insert(
        **expected_update_id,
        dtos::UpdateHash::Code(sha2::Sha256::digest(expected_update_code).into()),
    );

    let expected = dtos::ProposedUpdates {
        votes: expected_votes_map,
        updates: expected_updates_map,
    };

    assert_eq!(*actual_proposed_updates, expected);
}
