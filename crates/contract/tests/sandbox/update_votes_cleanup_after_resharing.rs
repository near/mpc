use crate::sandbox::{
    common::{SandboxTestSetup, chunked_upload_contract},
    utils::{
        consts::{GAS_FOR_VOTE_NEW_DOMAIN, GAS_FOR_VOTE_UPDATE},
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_state,
        },
        resharing_utils::do_resharing,
        transactions::execute_async_transactions,
    },
};
use anyhow::Result;
use mpc_contract::{
    primitives::{participants::Participants, thresholds::ThresholdParameters},
    update::{StartContractUploadArgs, UpdateId, UploadContractChunkArgs},
};
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_workspaces::{Account, types::NearToken};
use serde_json::json;
use sha2::Digest;
use std::collections::BTreeMap;

/// Tests that update votes from non-participants are cleared after resharing.
#[tokio::test]
async fn update_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // given: a running contract with PARTICIPANT_LEN participants and an update proposal with 2 votes
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    // Propose a code update via the chunked-upload flow, then have the first
    // two participants vote on it.
    let code = vec![1u8; 1000];
    let update_id: UpdateId =
        chunked_upload_contract(&worker, &mpc_signer_accounts[0], &contract, &code).await;

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
                account_id.clone(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    tls_public_key: participant_info.tls_public_key.clone(),
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
    let voter_id: &AccountId = votes_for_update[0];
    assert!(
        final_participants
            .participants
            .iter()
            .any(|(a, _, _)| a == voter_id)
    );

    Ok(())
}

/// An in-progress chunked upload owned by an account that resharing removes from
/// the participant set can never be finalized or cleared by its (now non-voter)
/// owner, so the post-resharing cleanup must drop it and refund the accumulated
/// deposit.
#[tokio::test]
async fn staged_uploads_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // Given: a running contract where participant 0 has an in-progress upload.
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    let uploader = &mpc_signer_accounts[0];
    let chunk = vec![7u8; 1000];
    let chunk_deposit = NearToken::from_near(1);

    uploader
        .call(contract.id(), method_names::START_CONTRACT_UPLOAD)
        .args_borsh(StartContractUploadArgs {
            total_size: std::num::NonZeroU64::new(chunk.len() as u64).unwrap(),
        })
        .max_gas()
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()
        .map_err(|e| anyhow::anyhow!("start_contract_upload failed: {e}"))?;

    uploader
        .call(contract.id(), method_names::UPLOAD_CONTRACT_CHUNK)
        .args_borsh(UploadContractChunkArgs {
            data: chunk.clone(),
        })
        .max_gas()
        .deposit(chunk_deposit)
        .transact()
        .await?
        .into_result()
        .map_err(|e| anyhow::anyhow!("upload_contract_chunk failed: {e}"))?;

    let balance_before = uploader.view_account().await?.balance;

    // When: resharing completes with new participants that exclude participant 0.
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants
        .iter()
        .skip(1)
        .take(threshold.0 as usize)
    {
        new_participants
            .insert_with_id(
                account_id.clone(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    tls_public_key: participant_info.tls_public_key.clone(),
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

    // Then: the cleanup promise refunds participant 0's accumulated deposit.
    // Participant 0 submits no transactions in this window, so its balance can
    // only increase, and only via the refund.
    let balance_after = uploader.view_account().await?.balance;
    assert!(
        balance_after > balance_before,
        "expected staged-upload deposit to be refunded after resharing: before={balance_before}, after={balance_after}"
    );

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
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    let next_domain_id = {
        let state: dtos::ProtocolContractState = get_state(&contract).await;
        let dtos::ProtocolContractState::Running(running) = &state else {
            panic!("Expected running state");
        };
        running.domains.next_domain_id
    };
    let domains_to_add = vec![DomainConfig {
        id: DomainId(next_domain_id),
        protocol: Protocol::Frost,
        reconstruction_threshold: ReconstructionThreshold::new(6),
        purpose: DomainPurpose::Sign,
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
                account_id.clone(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    tls_public_key: participant_info.tls_public_key.clone(),
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
        .map(|a| a.id().clone())
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
