use crate::indexer::participants::ContractState;
use crate::metrics::{MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE, MPC_OWNED_NUM_TRIPLES_AVAILABLE};
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
    (setup, runs)
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn cluster__should_presign_online_when_all_nodes_are_current() {
    // Given
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut setup, _runs) = running_cluster(temp_dir.path(), port_seed::ONLINE_PRESIGN_TEST).await;
    tokio::time::timeout(Duration::from_secs(120), async {
        while MPC_OWNED_NUM_TRIPLES_AVAILABLE.get() == 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("timeout waiting for triples");
    let online_presign_before = MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
        .with_label_values(&["online_presign"])
        .get();

    // When
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

    // Then
    let online_presign_after = MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
        .with_label_values(&["online_presign"])
        .get();
    assert!(online_presign_after > online_presign_before);
}
