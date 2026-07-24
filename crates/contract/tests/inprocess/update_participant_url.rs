#![allow(non_snake_case)]

use super::common::{
    init_contract, participant_context, participant_context_with_deposit,
    transition_to_initializing,
};
use mpc_contract::{
    MpcContract,
    errors::{Error, InvalidState},
    primitives::{
        test_utils::gen_participants,
        thresholds::{GovernanceThreshold, GovernanceThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    ParticipantInfo as DtoParticipantInfo, ProtocolContractStateCompat,
};
use near_sdk::{NearToken, testing_env};
use std::str::FromStr;

use assert_matches::assert_matches;

fn participant_info(contract: &MpcContract, account_id: &AccountId) -> DtoParticipantInfo {
    let ProtocolContractStateCompat::Running(running) = contract.state() else {
        panic!("expected Running state");
    };
    running
        .parameters
        .participants
        .participants
        .into_iter()
        .find(|(a, _, _)| a == account_id)
        .map(|(_, _, info)| info)
        .expect("participant should be present")
}

#[test]
fn update_participant_url__should_change_url_keeping_tls_key_and_id() {
    // Given
    let participants = gen_participants(3);
    let participant_list = participants.participants().clone();
    let parameters =
        GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
    let mut contract = init_contract(&parameters, None);
    let (account_id, _, original_info) = participant_list[0].clone();
    let (other_account, _, other_info) = participant_list[1].clone();
    let new_url = "https://relocated.example.com:9000".to_string();
    assert_ne!(original_info.url, new_url);

    // When
    testing_env!(participant_context_with_deposit(
        &account_id,
        NearToken::from_yoctonear(1)
    ));
    contract.update_participant_url(new_url.clone()).unwrap();

    // Then
    let updated = participant_info(&contract, &account_id);
    assert_eq!(updated.url, new_url);
    assert_eq!(updated.tls_public_key, original_info.tls_public_key);
    let other = participant_info(&contract, &other_account);
    assert_eq!(other.url, other_info.url);
}

#[test]
#[should_panic(expected = "Attached deposit is lower than required")]
fn update_participant_url__should_reject_when_no_deposit_attached() {
    // Given
    let participants = gen_participants(3);
    let participant_list = participants.participants().clone();
    let parameters =
        GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
    let mut contract = init_contract(&parameters, None);
    let (account_id, _, _) = participant_list[0].clone();

    // panics via `require_deposit` before the URL is updated
    // When, Then
    testing_env!(participant_context(&account_id));
    let _ = contract.update_participant_url("https://relocated.example.com:9000".to_string());
}

#[test]
fn update_participant_url__should_reject_non_participant() {
    // Given
    let participants = gen_participants(3);
    let parameters =
        GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
    let mut contract = init_contract(&parameters, None);
    let outsider = AccountId::from_str("outsider.near").unwrap();

    // When
    testing_env!(participant_context(&outsider));
    let result = contract.update_participant_url("https://outsider.example.com:9000".to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidState(InvalidState::NotParticipant { .. }))
    );
}

#[test]
fn update_participant_url__should_reject_when_not_running() {
    // Given
    let participants = gen_participants(3);
    let participant_list = participants.participants().clone();
    let parameters =
        GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
    let mut contract = init_contract(&parameters, None);
    transition_to_initializing(&mut contract, &participant_list);
    let (account_id, _, _) = participant_list[0].clone();

    // When
    testing_env!(participant_context(&account_id));
    let result = contract.update_participant_url("https://relocated.example.com:9000".to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidState(InvalidState::ProtocolStateNotRunning))
    );
}
