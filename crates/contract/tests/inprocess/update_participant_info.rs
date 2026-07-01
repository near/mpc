#![allow(non_snake_case)]

use mpc_contract::{
    MpcContract,
    crypto_shared::types::PublicKeyExtended,
    errors::{Error, InvalidParameters, InvalidState},
    primitives::{
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantId, ParticipantInfo},
        test_utils::gen_participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ProtocolContractState, ReconstructionThreshold,
};
use near_sdk::{VMContext, test_utils::VMContextBuilder, testing_env};
use std::str::FromStr;

use assert_matches::assert_matches;
use rstest::rstest;

fn participant_context(account_id: &AccountId) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .predecessor_account_id(account_id.clone())
        .build()
}

struct RunningContract {
    contract: MpcContract,
    participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

fn build_running_contract(participant_count: usize, threshold: u64) -> RunningContract {
    let participants = gen_participants(participant_count);
    let participants_list = participants.participants().clone();
    let parameters = ThresholdParameters::new(participants, Threshold::new(threshold))
        .expect("failed to create threshold parameters");

    let near_public_key =
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, vec![1u8; 64]).unwrap();
    let keyset = Keyset::new(
        EpochId::new(5),
        vec![KeyForDomain {
            domain_id: DomainId::default(),
            key: PublicKeyExtended::Secp256k1 { near_public_key },
            attempt: AttemptId::new(),
        }],
    );
    let domains = vec![DomainConfig {
        id: DomainId::default(),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(2),
        purpose: DomainPurpose::Sign,
    }];

    let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
    testing_env!(
        VMContextBuilder::new()
            .predecessor_account_id(contract_account_id.clone())
            .current_account_id(contract_account_id)
            .build()
    );

    let contract = MpcContract::init_running(domains, 1, keyset, parameters.into(), None).unwrap();

    RunningContract {
        contract,
        participants: participants_list,
    }
}

/// Drives the contract out of `Running` by having every participant vote to add a new domain,
/// which transitions it into `Initializing`.
fn transition_to_initializing(rc: &mut RunningContract) {
    for (account_id, _, _) in rc.participants.clone() {
        testing_env!(participant_context(&account_id));
        rc.contract
            .vote_add_domains(vec![DomainConfig {
                id: DomainId(1),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            }])
            .unwrap();
    }
    assert_matches!(rc.contract.state(), ProtocolContractState::Initializing(_));
}

#[test]
fn update_participant_info__should_change_url_keeping_tls_key_and_id() {
    // Given
    let mut rc = build_running_contract(3, 2);
    let (account_id, expected_id, original_info) = rc.participants[0].clone();
    let new_url = "https://relocated.example.com:9000".to_string();
    assert_ne!(original_info.url, new_url);

    // When
    testing_env!(participant_context(&account_id));
    rc.contract
        .update_participant_info(new_url.clone())
        .unwrap();

    // Then
    let ProtocolContractState::Running(running) = rc.contract.state() else {
        panic!("expected Running state");
    };
    let updated = running
        .parameters
        .participants
        .participants
        .iter()
        .find(|(a, _, _)| *a == account_id)
        .expect("participant should still be present");
    assert_eq!(updated.1, expected_id);
    assert_eq!(updated.2.url, new_url);
    assert_eq!(updated.2.tls_public_key, original_info.tls_public_key);

    // Other participants are untouched.
    let (other_account, _, other_info) = rc.participants[1].clone();
    let other = running
        .parameters
        .participants
        .participants
        .iter()
        .find(|(a, _, _)| *a == other_account)
        .expect("other participant should still be present");
    assert_eq!(other.2.url, other_info.url);
}

#[test]
fn update_participant_info__should_reject_non_participant() {
    // Given
    let mut rc = build_running_contract(3, 2);
    let outsider = AccountId::from_str("outsider.near").unwrap();

    // When
    testing_env!(participant_context(&outsider));
    let result = rc
        .contract
        .update_participant_info("https://outsider.example.com:9000".to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidState(InvalidState::NotParticipant { .. }))
    );
}

#[test]
fn update_participant_info__should_reject_when_not_running() {
    // Given
    let mut rc = build_running_contract(3, 2);
    transition_to_initializing(&mut rc);
    let (account_id, _, _) = rc.participants[0].clone();

    // When
    testing_env!(participant_context(&account_id));
    let result = rc
        .contract
        .update_participant_info("https://relocated.example.com:9000".to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidState(InvalidState::ProtocolStateNotRunning))
    );
}

#[rstest]
#[case("")]
#[case("   ")]
#[case("not-a-url")]
#[case("://nohost")]
#[case("https://")]
fn update_participant_info__should_reject_malformed_url(#[case] bad_url: &str) {
    // Given
    let mut rc = build_running_contract(3, 2);
    let (account_id, _, original_info) = rc.participants[0].clone();

    // When
    testing_env!(participant_context(&account_id));
    let result = rc.contract.update_participant_info(bad_url.to_string());

    // Then
    assert_matches!(
        result,
        Err(Error::InvalidParameters(
            InvalidParameters::InvalidUrl { .. }
        ))
    );
    let ProtocolContractState::Running(running) = rc.contract.state() else {
        panic!("expected Running state");
    };
    let stored = running
        .parameters
        .participants
        .participants
        .iter()
        .find(|(a, _, _)| *a == account_id)
        .expect("participant should still be present");
    assert_eq!(stored.2.url, original_info.url);
}
