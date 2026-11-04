use crate::indexer::participants::ContractState;
use crate::p2p::testing::port_seed;
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    IntegrationTestSetup, every_node_owns_triples, request_ckd_and_await_response,
    request_ckd_pv_and_await_response, request_signature_and_await_response, wait_until,
};
use crate::tracking::AutoAbortTask;
use mpc_node_config::TripleBatchSize;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_time::Clock;

const NUM_PARTICIPANTS: usize = 4;
const GOVERNANCE_THRESHOLD: usize = 3;
const TXN_DELAY_BLOCKS: u64 = 1;

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn cluster__should_serve_every_domain_after_keygen() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::BASIC_CLUSTER_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let signature_domain_ecdsa = DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(3),
        purpose: DomainPurpose::Sign,
    };

    let signature_domain_eddsa = DomainConfig {
        id: DomainId(1),
        protocol: Protocol::Frost,
        reconstruction_threshold: ReconstructionThreshold::new(3),
        purpose: DomainPurpose::Sign,
    };

    let ckd_domain = DomainConfig {
        id: DomainId(2),
        protocol: Protocol::ConfidentialKeyDerivation,
        reconstruction_threshold: ReconstructionThreshold::new(3),
        purpose: DomainPurpose::CKD,
    };

    let domains = vec![
        signature_domain_ecdsa.clone(),
        signature_domain_eddsa.clone(),
        ckd_domain.clone(),
    ];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
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
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    wait_until(
        || every_node_owns_triples(NUM_PARTICIPANTS),
        "every node to own triples",
    )
    .await;
    assert!(
        request_signature_and_await_response(
            &mut setup.indexer,
            "user0",
            &signature_domain_ecdsa,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some()
    );

    assert!(
        request_signature_and_await_response(
            &mut setup.indexer,
            "user0",
            &signature_domain_eddsa,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some()
    );

    assert!(
        request_ckd_and_await_response(
            &mut setup.indexer,
            "user0",
            &ckd_domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some()
    );

    assert!(
        request_ckd_pv_and_await_response(
            &mut setup.indexer,
            "user0",
            &ckd_domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some()
    );
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn cluster__should_generate_triples_with_a_non_legacy_batch_size() {
    // Given
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{i}").parse().unwrap())
            .collect(),
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::TRIPLE_BATCH_SIZE_TEST,
        DEFAULT_BLOCK_TIME,
    );
    for node in &mut setup.configs {
        node.config.triple.batch_size = TripleBatchSize::new(8).unwrap();
    }
    let domain = DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(3),
        purpose: DomainPurpose::Sign,
    };
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain]);
    }

    // When
    let _runs = std::mem::take(&mut setup.configs)
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

    // Then
    // a batch only succeeds once every follower accepts its size
    wait_until(
        || every_node_owns_triples(NUM_PARTICIPANTS),
        "led triple batches to succeed",
    )
    .await;
}
