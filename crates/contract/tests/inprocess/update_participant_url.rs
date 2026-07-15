#![allow(non_snake_case)]

use super::common::{
    RunningContract, build_running_contract, participant_context, transition_to_initializing,
};
use mpc_contract::errors::{Error, InvalidState};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    ParticipantInfo as DtoParticipantInfo, ProtocolContractState,
};
use near_sdk::testing_env;
use std::str::FromStr;

use assert_matches::assert_matches;

fn participant_info(rc: &RunningContract, account_id: &AccountId) -> DtoParticipantInfo {
    let ProtocolContractState::Running(running) = rc.contract.state() else {
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
    let mut rc = build_running_contract(3, 2, None);
    let (account_id, _, original_info) = rc.participants[0].clone();
    let (other_account, _, other_info) = rc.participants[1].clone();
    let new_url = "https://relocated.example.com:9000".to_string();
    assert_ne!(original_info.url, new_url);

    // When
    testing_env!(participant_context(&account_id));
    rc.contract.update_participant_url(new_url.clone()).unwrap();

    // Then
    let updated = participant_info(&rc, &account_id);
    assert_eq!(updated.url, new_url);
    assert_eq!(updated.tls_public_key, original_info.tls_public_key);
    let other = participant_info(&rc, &other_account);
    assert_eq!(other.url, other_info.url);
}

#[test]
fn update_participant_url__should_reject_non_participant() {
    // Given
    let mut rc = build_running_contract(3, 2, None);
    let outsider = AccountId::from_str("outsider.near").unwrap();

    // When
    testing_env!(participant_context(&outsider));
    let result = rc
        .contract
        .update_participant_url("https://outsider.example.com:9000".to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidState(InvalidState::NotParticipant { .. }))
    );
}

#[test]
fn update_participant_url__should_reject_when_not_running() {
    // Given
    let mut rc = build_running_contract(3, 2, None);
    let participants = rc.participants.clone();
    transition_to_initializing(&mut rc.contract, &participants);
    let (account_id, _, _) = rc.participants[0].clone();

    // When
    testing_env!(participant_context(&account_id));
    let result = rc
        .contract
        .update_participant_url("https://relocated.example.com:9000".to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidState(InvalidState::ProtocolStateNotRunning))
    );
}
