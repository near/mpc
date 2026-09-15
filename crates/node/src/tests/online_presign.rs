use crate::indexer::participants::ContractState;
use crate::metrics::{
    MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE, MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE,
    MPC_OWNED_NUM_TRIPLES_AVAILABLE, ONLINE_PRESIGN_MODE_LABEL, STORED_PRESIGNATURE_MODE_LABEL,
};
use crate::p2p::testing::port_seed;
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
use std::time::Duration;
use test_port_allocator::TestPorts;

const NUM_PARTICIPANTS: usize = 4;
const GOVERNANCE_THRESHOLD: usize = 3;
const TXN_DELAY_BLOCKS: u64 = 1;

fn ecdsa_domain() -> DomainConfig {
    DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(3),
        purpose: DomainPurpose::Sign,
    }
}

/// Boots a cluster with one cait-sith domain and waits until the network is running.
async fn running_cluster(
    temp_dir: &std::path::Path,
    ports: TestPorts,
    online_presign: bool,
) -> (IntegrationTestSetup, Vec<AutoAbortTask<anyhow::Result<()>>>) {
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir,
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{i}").parse().unwrap())
            .collect(),
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        ports,
        DEFAULT_BLOCK_TIME,
    );
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![ecdsa_domain()]);
    }
    let runs = std::mem::take(&mut setup.configs)
        .into_iter()
        .map(|mut config| {
            config.config.signature.online_presign = online_presign;
            AutoAbortTask::from(tokio::spawn(config.run()))
        })
        .collect::<Vec<_>>();
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for keygen to complete");
    (setup, runs)
}

async fn wait_until_available(gauge: &prometheus::IntGauge) {
    tokio::time::timeout(Duration::from_secs(120), async {
        while gauge.get() == 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("timeout waiting for assets");
}

fn signatures_led(mode: &str) -> u64 {
    MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
        .with_label_values(&[mode])
        .get()
}

async fn request_three_signatures(setup: &mut IntegrationTestSetup) {
    for user in ["user0", "user1", "user2"] {
        assert!(
            request_signature_and_await_response(
                &mut setup.indexer,
                user,
                &ecdsa_domain(),
                DEFAULT_MAX_SIGNATURE_WAIT_TIME,
            )
            .await
            .is_some()
        );
    }
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn cluster__should_presign_online_when_all_nodes_are_current() {
    // Given
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut setup, _runs) =
        running_cluster(temp_dir.path(), port_seed::ONLINE_PRESIGN_TEST, true).await;
    wait_until_available(&MPC_OWNED_NUM_TRIPLES_AVAILABLE).await;
    let online_presign_before = signatures_led(ONLINE_PRESIGN_MODE_LABEL);

    // When
    request_three_signatures(&mut setup).await;

    // Then
    assert!(signatures_led(ONLINE_PRESIGN_MODE_LABEL) > online_presign_before);
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn cluster__should_sign_from_stored_presignatures_when_config_disables_online_presign() {
    // Given
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut setup, _runs) = running_cluster(
        temp_dir.path(),
        port_seed::ONLINE_PRESIGN_DISABLED_TEST,
        false,
    )
    .await;
    wait_until_available(&MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE).await;
    let online_presign_before = signatures_led(ONLINE_PRESIGN_MODE_LABEL);
    let stored_presignature_before = signatures_led(STORED_PRESIGNATURE_MODE_LABEL);

    // When
    request_three_signatures(&mut setup).await;

    // Then
    assert_eq!(
        signatures_led(ONLINE_PRESIGN_MODE_LABEL),
        online_presign_before
    );
    assert!(signatures_led(STORED_PRESIGNATURE_MODE_LABEL) > stored_presignature_before);
}
