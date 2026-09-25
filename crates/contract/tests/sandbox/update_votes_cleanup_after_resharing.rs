use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_state,
        },
        resharing_utils::do_resharing,
        transactions::execute_async_handle_calls,
    },
};
use anyhow::Result;
use mpc_contract::primitives::{
    participants::Participants, thresholds::GovernanceThresholdParameters,
};
use mpc_primitives::hash::ProposalHash;
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold, Update, UpdateHash,
};
use near_mpc_sdk::update::hash;
use near_workspaces::Account;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

#[tokio::test]
async fn contract_update_votes_from_kicked_out_participants_are_cleared_after_resharing()
-> Result<()> {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;

    let update_hash = hash(&Update::Code(vec![1u8; 1000]));
    execute_async_handle_calls(&mpc_signer_accounts[0..2], &contract, |handle| {
        let update_hash = update_hash.clone();
        async move { handle.vote_contract_update(update_hash).await }
    })
    .await?;

    let votes_before: BTreeMap<ProposalHash, BTreeSet<AccountId>> = contract
        .view(method_names::CONTRACT_UPDATE_VOTES)
        .await?
        .json()?;

    assert_eq!(
        votes_before,
        expected_contract_update_votes(&update_hash, &mpc_signer_accounts[0..2])
    );

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
                    url: participant_info.url.clone().try_into().unwrap(),
                    tls_public_key: participant_info.tls_public_key.clone(),
                },
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .map_err(|e| anyhow::anyhow!("Failed to insert participant: {}", e))?;
    }

    let new_threshold_parameters = GovernanceThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::GovernanceThreshold::new(threshold.0),
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
    let final_participants = assert_running_return_participants(&contract).await?;
    let votes_after: BTreeMap<ProposalHash, BTreeSet<AccountId>> = contract
        .view(method_names::CONTRACT_UPDATE_VOTES)
        .await?
        .json()?;

    assert_eq!(
        votes_after,
        expected_contract_update_votes(&update_hash, &mpc_signer_accounts[1..2])
    );

    let remaining_voters: Vec<&AccountId> = votes_after.values().flatten().collect();
    assert_eq!(remaining_voters.len(), 1);
    let voter_id: &AccountId = remaining_voters[0];
    assert!(
        final_participants
            .participants
            .iter()
            .any(|(a, _, _)| a == voter_id)
    );

    Ok(())
}

/// Tests that add_domain votes from participants who are removed during resharing
/// are cleaned up, while votes from remaining participants are preserved.
#[tokio::test]
async fn add_domain_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // Given
    let SandboxTestSetup {
        worker: _worker,
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
    execute_async_handle_calls(&mpc_signer_accounts[0..2], &contract, |handle| {
        let domains_to_add = domains_to_add.clone();
        async move { handle.vote_add_domains(domains_to_add).await }
    })
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
                    url: participant_info.url.clone().try_into().unwrap(),
                    tls_public_key: participant_info.tls_public_key.clone(),
                },
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .map_err(|e| anyhow::anyhow!("Failed to insert participant: {}", e))?;
    }

    let new_threshold_parameters = GovernanceThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::GovernanceThreshold::new(threshold.0),
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

fn expected_contract_update_votes(
    update_hash: &UpdateHash,
    voters: &[Account],
) -> BTreeMap<ProposalHash, BTreeSet<AccountId>> {
    let key =
        ProposalHash::new(sha2::Sha256::digest(serde_json::to_vec(update_hash).unwrap()).into());
    BTreeMap::from([(key, voters.iter().map(|a| a.id().clone()).collect())])
}
