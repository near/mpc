use crate::sandbox::{
    common::{init_env, SandboxTestSetup},
    utils::{
        consts::{CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_VOTE_UPDATE, PARTICIPANT_LEN},
        interface::IntoContractType,
        mpc_contract::{assert_running_return_participants, assert_running_return_threshold},
        resharing_utils::do_resharing,
        transactions::execute_async_transactions,
    },
};
use anyhow::Result;
use contract_interface::types as dtos;
use mpc_contract::{
    primitives::{
        domain::SignatureScheme, participants::Participants, thresholds::ThresholdParameters,
    },
    update::{ProposeUpdateArgs, UpdateId},
};
use near_account_id::AccountId;
use near_workspaces::Account;
use serde_json::json;
use sha2::Digest;
use std::collections::BTreeMap;

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

    // when: resharing completes with new participants that exclude mpc_signer_accounts[0]
    // Build new_participants from all participants except the first account (by creation order)
    let excluded_account = mpc_signer_accounts[0].id().to_string();
    // Build new participants: all except mpc_signer_accounts[0]
    let subset_dto = dtos::Participants {
        next_id: initial_participants.next_id,
        participants: initial_participants
            .participants
            .iter()
            .filter(|(account_id, _)| account_id.0 != excluded_account)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    let new_participants: Participants = (&subset_dto).into_contract_type();

    // Filter mpc_signer_accounts to only include accounts in new_participants
    let remaining_accounts: Vec<Account> = mpc_signer_accounts
        .iter()
        .filter(|a| *a.id() != excluded_account)
        .cloned()
        .collect();

    let new_threshold_parameters = ThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::Threshold::new(threshold.0),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    let prospective_epoch_id = dtos::EpochId(6);

    // when: resharing completes with new participants that exclude participant 0
    do_resharing(
        &remaining_accounts,
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
    assert!(final_participants
        .participants
        .keys()
        .any(|a| a.0.as_str() == voter_id.as_str()));

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
        .map(|a| dtos::AccountId(a.id().to_string()))
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
