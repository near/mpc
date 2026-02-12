use crate::indexer::participants::ContractState;
use crate::metrics;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_ckd_and_await_response, request_signature_and_await_response, IntegrationTestSetup,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_time::Clock;
use rstest::rstest;
use serial_test::serial;

use super::DEFAULT_BLOCK_TIME;

// Test a simple resharing of one node joining a cluster of 4 nodes.
#[tokio::test]
#[test_log::test]
#[rstest]
#[case(0, SignatureScheme::Secp256k1, 3)]
#[case(1, SignatureScheme::Ed25519, 3)]
#[case(2, SignatureScheme::Bls12381, 3)]
// TODO(#1946): re-enable once it is no longer flaky
// #[case(3, SignatureScheme::V2Secp256k1, 5)]
async fn test_key_resharing_simple(
    #[case] case: u16,
    #[case] scheme: SignatureScheme,
    #[case] threshold: usize,
) {
    let num_participants: usize = threshold + 1;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..num_participants)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        threshold,
        TXN_DELAY_BLOCKS,
        PortSeed::KEY_RESHARING_SIMPLE_TEST.with_case(case),
        DEFAULT_BLOCK_TIME,
    );

    // Initialize the contract with one fewer participant.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    let domain = DomainConfig {
        id: DomainId(0),
        scheme,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(initial_participants);
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
        .expect("must not exceed timeout");

    // Sanity check.
    match domain.scheme {
        SignatureScheme::Secp256k1 | SignatureScheme::Ed25519 | SignatureScheme::V2Secp256k1 => {
            assert!(request_signature_and_await_response(
                &mut setup.indexer,
                "user1",
                &domain,
                DEFAULT_MAX_SIGNATURE_WAIT_TIME
            )
            .await
            .is_some());
        }
        SignatureScheme::Bls12381 => {
            assert!(request_ckd_and_await_response(
                &mut setup.indexer,
                "user1",
                &domain,
                DEFAULT_MAX_SIGNATURE_WAIT_TIME
            )
            .await
            .is_some());
        }
    }

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
                        && running.participants.participants.len() == num_participants
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    match domain.scheme {
        SignatureScheme::Secp256k1 | SignatureScheme::Ed25519 | SignatureScheme::V2Secp256k1 => {
            assert!(request_signature_and_await_response(
                &mut setup.indexer,
                "user1",
                &domain,
                DEFAULT_MAX_SIGNATURE_WAIT_TIME
            )
            .await
            .is_some());
        }
        SignatureScheme::Bls12381 => {
            assert!(request_ckd_and_await_response(
                &mut setup.indexer,
                "user1",
                &domain,
                DEFAULT_MAX_SIGNATURE_WAIT_TIME
            )
            .await
            .is_some());
        }
    }
}

// Test two nodes joining and two old nodes leaving.
#[tokio::test]
#[test_log::test]
async fn test_key_resharing_multistage() {
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
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(participants_1);
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
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 0
                        && running.participants.participants.len() == NUM_PARTICIPANTS - 2
                        && running.keyset.get_domain_ids().len() == 1
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
    )
    .await
    .is_some());

    // Have the fifth node join.
    let mut participants_2 = setup.participants.clone();
    participants_2.participants.pop();
    participants_2.threshold = 3;
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
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
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
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
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
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
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
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
    )
    .await
    .is_some());
}

/// Test that signatures during resharing
/// are also processed.
#[serial] // this test relies on metrics for timing
#[tokio::test]
#[test_log::test]
async fn test_signature_requests_in_resharing_are_processed() {
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
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(initial_participants);
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

    request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await
    .expect("Timed out generating the first signature");

    // Disable a node to make resharing stall.
    let disabled = setup.indexer.disable(0.into()).await;

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
    request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
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
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Protocol state must change within timeout period.");

    // Send a request for signature.
    request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await
    .expect("Signature request in running should be processed.");
}
