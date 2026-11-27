use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        interface::IntoContractType, mpc_contract::get_state, resharing_utils::do_resharing,
        sandbox_mpc_contract::SandboxMpcContract, transactions::execute_async_handle_calls,
    },
};
use anyhow::Result;
use mpc_contract::primitives::{
    participants::Participants, thresholds::GovernanceThresholdParameters,
};
use mpc_primitives::hash::ProposalHash;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold, Update, UpdateHash,
};
use near_mpc_sdk::update::hash;
use near_workspaces::Account;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

const NUM_VOTERS: usize = 2;

#[tokio::test]
#[expect(non_snake_case)]
async fn vote_reshared__should_sweep_contract_update_votes_of_kicked_out_participants() -> Result<()>
{
    // Given
    let setup = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;
    let (contract, accounts) = (&setup.contract, &setup.mpc_signer_accounts);
    let voters = &accounts[..NUM_VOTERS];
    let update_hash = hash(&Update::Code(vec![1u8; 1000]));
    execute_async_handle_calls(voters, contract, |handle| {
        let update_hash = update_hash.clone();
        async move { handle.vote_contract_update(update_hash).await }
    })
    .await?;

    // When
    reshare_without_first_participant(contract, accounts).await?;

    // Then
    let (_, remaining_voters) = voters.split_first().unwrap();
    assert_eq!(
        contract.contract_update_votes().await?.value,
        expected_contract_update_votes(&update_hash, remaining_voters)
    );

    Ok(())
}

/// Tests that add_domain votes from participants who are removed during resharing
/// are cleaned up, while votes from remaining participants are preserved.
#[tokio::test]
async fn add_domain_votes_from_kicked_out_participants_are_cleared_after_resharing() -> Result<()> {
    // Given
    let setup = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;
    let (contract, accounts) = (&setup.contract, &setup.mpc_signer_accounts);
    let dtos::ProtocolContractState::Running(running) = get_state(contract).await else {
        panic!("expected running state");
    };
    let domains_to_add = vec![DomainConfig {
        id: running.domains.next_domain_id,
        protocol: Protocol::Frost,
        reconstruction_threshold: ReconstructionThreshold::new(6),
        purpose: DomainPurpose::Sign,
    }];
    execute_async_handle_calls(&accounts[..NUM_VOTERS], contract, |handle| {
        let domains_to_add = domains_to_add.clone();
        async move { handle.vote_add_domains(domains_to_add).await }
    })
    .await?;

    // When
    reshare_without_first_participant(contract, accounts).await?;

    // Then
    let (_, remaining_voters) = running.parameters.participants.participants[..NUM_VOTERS]
        .split_first()
        .unwrap();
    let proposal =
        ProposalHash::new(sha2::Sha256::digest(borsh::to_vec(&domains_to_add).unwrap()).into());
    assert_eq!(
        contract.add_domains_votes().await?.value,
        dtos::AddDomainsVotes(BTreeMap::from([(
            proposal,
            remaining_voters
                .iter()
                .map(|(_, id, _)| dtos::AuthenticatedParticipantId(*id))
                .collect()
        )]))
    );

    Ok(())
}

/// Reshares away the first participant: the threshold of participants after it vote for
/// themselves, keeping the threshold.
async fn reshare_without_first_participant(
    contract: &SandboxMpcContract,
    accounts: &[Account],
) -> Result<()> {
    let dtos::ProtocolContractState::Running(running) = get_state(contract).await else {
        panic!("expected running state");
    };
    let threshold = running.parameters.threshold;
    let remaining = 1..usize::try_from(threshold.value())? + 1;
    let participants: Participants = (&running.parameters.participants).into_contract_type();
    let parameters =
        GovernanceThresholdParameters::new(participants.subset(remaining.clone()), threshold)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    do_resharing(
        &accounts[remaining],
        contract,
        parameters,
        running.keyset.epoch_id.next(),
    )
    .await
}

fn expected_contract_update_votes(
    update_hash: &UpdateHash,
    voters: &[Account],
) -> BTreeMap<ProposalHash, BTreeSet<AccountId>> {
    let key =
        ProposalHash::new(sha2::Sha256::digest(serde_json::to_vec(update_hash).unwrap()).into());
    BTreeMap::from([(key, voters.iter().map(|a| a.id().clone()).collect())])
}
