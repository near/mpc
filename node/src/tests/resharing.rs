use crate::indexer::participants::ContractState;
use crate::metrics;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_signature_and_await_response, IntegrationTestSetup, DEFAULT_MAX_PROTOCOL_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, DomainProtocol};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use serial_test::serial;

use super::DEFAULT_BLOCK_TIME;

// Test a simple resharing of one node joining a cluster of 4 nodes.
#[tokio::test]
async fn test_key_resharing_simple() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
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
        PortSeed::KEY_RESHARING_SIMPLE_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Initialize the contract with one fewer participant.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    let domain = DomainConfig {
        id: DomainId(0),
        protocol: DomainProtocol::SignSecp256k1,
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

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants);

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 1
                        && running.participants.participants.len() == NUM_PARTICIPANTS
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}

// Test two nodes joining and two old nodes leaving.
#[tokio::test]
async fn test_key_resharing_multistage() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 6;
    const THRESHOLD: usize = 4;
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
        PortSeed::KEY_RESHARING_MULTISTAGE_TEST,
        std::time::Duration::from_millis(600),
    );

    // Initialize the contract with two fewer participants.
    let mut participants_1 = setup.participants.clone();
    participants_1.participants.pop();
    participants_1.participants.pop();
    participants_1.threshold = 3;

    let domain = DomainConfig {
        id: DomainId(0),
        protocol: DomainProtocol::SignSecp256k1,
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

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the fifth node join.
    let mut participants_2 = setup.participants.clone();
    participants_2.participants.pop();
    participants_1.threshold = 3;
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(participants_2);

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 1
                        && running.participants.participants.len() == NUM_PARTICIPANTS - 1
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the sixth node join.
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants.clone());
    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 2
                        && running.participants.participants.len() == NUM_PARTICIPANTS
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user2",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the first node quit.
    let mut participants_3 = setup.participants.clone();
    participants_3.participants.remove(0);
    participants_3.threshold = 3;
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(participants_3);

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 3
                        && running.participants.participants.len() == NUM_PARTICIPANTS - 1
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the second node quit.
    let mut participants_4 = setup.participants.clone();
    participants_4.participants.remove(0);
    participants_4.participants.remove(0);
    participants_4.threshold = 3;
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(participants_4);

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 4
                        && running.participants.participants.len() == NUM_PARTICIPANTS - 2
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}

/// Test that signatures during resharing
/// are also processed.
#[serial] // this test relies on metrics for timing
#[tokio::test]
async fn test_signature_requests_in_resharing_are_processed() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
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
        PortSeed::KEY_RESHARING_SIGNATURE_BUFFERING_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Initialize the contract with one fewer participant.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    let domain = DomainConfig {
        id: DomainId(0),
        protocol: DomainProtocol::SignSecp256k1,
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
        .expect("Protocol state must change within timeout period.");

    let response_time = request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("Timed out generating the first signature");

    // Disable a node to make resharing stall.
    let min_id = setup
        .participants
        .participants
        .iter()
        .map(|p| &p.id)
        .min()
        .unwrap();

    let to_disable = setup
        .participants
        .participants
        .iter()
        .find(|p| p.id != *min_id)
        .expect("No participant with non-minimum ID found")
        .near_account_id
        .clone();

    tracing::error!("disabling: {}", to_disable);
    let disabled = setup.indexer.disable(to_disable).await;

    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants);

    // Give nodes some time to transition into resharing state.
    for i in 0..20 {
        // We're running with [serial] so querying metrics should be OK.
        if let Ok(metric) =
            metrics::MPC_CURRENT_JOB_STATE.get_metric_with_label_values(&["Resharing"])
        {
            if metric.get() == NUM_PARTICIPANTS as i64 - 1 {
                break;
            }
        }
        if i == 19 {
            panic!("Timeout waiting for resharing to start");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Send a request for signature.
    request_signature_and_await_response(&mut setup.indexer, "user1", &domain, response_time * 2)
        .await
        .expect("Signature requests during resharing are processed.");

    // Re-enable the node.
    drop(disabled);

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => running.resharing_state.is_none(),
                _ => false,
            },
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("Protocol state must change within timeout period.");

    // Send a request for signature.
    request_signature_and_await_response(&mut setup.indexer, "user1", &domain, response_time * 2)
        .await
        .expect("Signature request in running should be processed.");
}
