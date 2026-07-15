#![allow(non_snake_case)]

use crate::indexer::fake::participant_info_from_config;
use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    IntegrationTestSetup, request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_time::Clock;

/// A peer's registered URL becoming unroutable (identity and port unchanged) does not stop the
/// running network: the change is hot-swapped, so established connections stay up and signing
/// continues.
#[tokio::test]
#[test_log::test]
async fn update_participant_url__should_keep_signing_when_peer_address_moved_to_dead_address() {
    // Given
    const NUM_PARTICIPANTS: usize = 2;
    const THRESHOLD: usize = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::UPDATE_PARTICIPANT_URL_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let domain = DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(2),
        purpose: DomainPurpose::Sign,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    assert!(
        request_signature_and_await_response(
            &mut setup.indexer,
            "user0",
            &domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some()
    );

    // When
    let mut moved_info = setup.participants.participants[1].clone();
    moved_info.address = "192.0.2.1".to_string();
    setup.indexer.contract_mut().await.update_participant_info(
        moved_info.near_account_id.clone(),
        participant_info_from_config(&moved_info),
    );

    // Then
    assert!(
        request_signature_and_await_response(
            &mut setup.indexer,
            "user1",
            &domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some()
    );
}
