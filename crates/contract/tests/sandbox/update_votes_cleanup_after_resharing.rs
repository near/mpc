use crate::sandbox::{
    common::{init_env, SandboxTestSetup},
    utils::{
        consts::{
            CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_VOTE_NEW_DOMAIN, GAS_FOR_VOTE_UPDATE,
            PARTICIPANT_LEN,
        },
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_state,
        },
        resharing_utils::do_resharing,
        transactions::execute_async_transactions,
    },
};
use anyhow::Result;
use contract_interface::method_names;
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
        .call(contract.id(), method_names::PROPOSE_UPDATE)
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
        method_names::VOTE_UPDATE,
        &json!({"id": update_id}),
        GAS_FOR_VOTE_UPDATE,
    )
    .await?;

    let proposals_before: dtos::ProposedUpdates = contract
        .view(method_names::PROPOSED_UPDATES)
        .await?
        .json()?;

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
        .participants
        .iter()
        .skip(1) // Skip participant 0, so participant 1-6 are included
        .take(threshold.0 as usize)
    {
        new_participants
            .insert_with_id(
                account_id.0.parse::<near_account_id::AccountId>().unwrap(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    sign_pk: participant_info.sign_pk.parse().unwrap(),
                },
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .map_err(|e| anyhow::anyhow!("Failed to insert participant: {}", e))?;
    }

    let new_threshold_parameters = ThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::Threshold::new(threshold.0),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    let prospective_epoch_id = dtos::EpochId(6);

    // when: resharing completes with new participants that exclude participant 0
    do_resharing(
        &mpc_signer_accounts[1..threshold.0 as usize + 1],
        &contract,
        new_threshold_parameters,
        prospective_epoch_id,
    )
    .await?;

    // then: the cleanup promise removes participant 0's vote from storage
    let final_participants = assert_running_return_participants(&contract).await?;
    let proposals_after: dtos::ProposedUpdates = contract
        .view(method_names::PROPOSED_UPDATES)
        .await?
        .json()?;

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
        .iter()
        .any(|(a, _, _)| a.0.as_str() == voter_id.as_str()));

    Ok(())
}

/// Tests that add_domain votes from participants who are removed during resharing
/// are cleaned up, while votes from remaining participants are preserved.
#[tokio::test]
async fn add_domain_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // Given
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    let next_domain_id = {
        let state: dtos::ProtocolContractState = get_state(&contract).await;
        let dtos::ProtocolContractState::Running(running) = &state else {
            panic!("Expected running state");
        };
        running.domains.next_domain_id
    };
    let domains_to_add = vec![dtos::DomainConfig {
        id: dtos::DomainId(next_domain_id),
        scheme: dtos::SignatureScheme::Ed25519,
        purpose: Some(dtos::DomainPurpose::Sign),
    }];
    execute_async_transactions(
        &mpc_signer_accounts[0..2],
        &contract,
        method_names::VOTE_ADD_DOMAINS,
        &json!({"domains": domains_to_add}),
        GAS_FOR_VOTE_NEW_DOMAIN,
    )
    .await?;

    let state: dtos::ProtocolContractState = get_state(&contract).await;
    let dtos::ProtocolContractState::Running(running) = &state else {
        panic!("Expected running state");
    };
    assert_eq!(running.add_domains_votes.proposal_by_account.len(), 2);

    // When
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants
        .iter()
        .skip(1)
        .take(threshold.0 as usize)
    {
        new_participants
            .insert_with_id(
                account_id.0.parse::<near_account_id::AccountId>().unwrap(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    sign_pk: participant_info.sign_pk.parse().unwrap(),
                },
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .map_err(|e| anyhow::anyhow!("Failed to insert participant: {}", e))?;
    }

    let new_threshold_parameters = ThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::Threshold::new(threshold.0),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    let prospective_epoch_id = dtos::EpochId(6);

    do_resharing(
        &mpc_signer_accounts[1..threshold.0 as usize + 1],
        &contract,
        new_threshold_parameters,
        prospective_epoch_id,
    )
    .await?;

    // Then
    let final_state: dtos::ProtocolContractState = get_state(&contract).await;
    let dtos::ProtocolContractState::Running(final_running) = &final_state else {
        panic!("Expected running state after resharing");
    };

    assert_eq!(final_running.add_domains_votes.proposal_by_account.len(), 1);

    let expected_remaining_voter_id = &initial_participants.participants[1].1;
    let remaining_voter_id = &final_running
        .add_domains_votes
        .proposal_by_account
        .keys()
        .next()
        .expect("Expected one remaining vote")
        .0;
    assert_eq!(remaining_voter_id, expected_remaining_voter_id);

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
