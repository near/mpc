use crate::indexer::participants::ContractState;
use crate::metrics::{
    MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE, MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE,
    MPC_OWNED_NUM_TRIPLES_AVAILABLE, ONLINE_PRESIGN_MODE_LABEL, STORED_PRESIGNATURE_MODE_LABEL,
};
use crate::p2p::testing::port_seed;
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    IntegrationTestSetup, request_ckd_and_await_response, request_ckd_pv_and_await_response,
    request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_time::Clock;
use prometheus::core::Collector;

const NUM_PARTICIPANTS: usize = 4;
const GOVERNANCE_THRESHOLD: usize = 3;
const TXN_DELAY_BLOCKS: u64 = 1;

fn signatures_led(mode: &str) -> u64 {
    MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
        .with_label_values(&[mode])
        .get()
}

fn gauge_total(gauge: &prometheus::IntGaugeVec) -> i64 {
    gauge
        .collect()
        .iter()
        .flat_map(|family| family.get_metric())
        .map(|metric| metric.get_gauge().get_value() as i64)
        .sum()
}

async fn wait_until_positive(gauge: &prometheus::IntGaugeVec, what: &str) {
    tokio::time::timeout(DEFAULT_MAX_PROTOCOL_WAIT_TIME, async {
        while gauge_total(gauge) == 0 {
            tokio::time::sleep(DEFAULT_BLOCK_TIME).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {what}"));
}

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
#[test_log::test]
async fn test_basic_cluster() {
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

    wait_until_positive(&MPC_OWNED_NUM_TRIPLES_AVAILABLE, "triples").await;
    wait_until_positive(&MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE, "presignatures").await;
    let stored_presignature_before = signatures_led(STORED_PRESIGNATURE_MODE_LABEL);
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
    // Every node runs the current version, so the default configuration presigns online.
    assert!(signatures_led(ONLINE_PRESIGN_MODE_LABEL) > 0);
    assert_eq!(
        signatures_led(STORED_PRESIGNATURE_MODE_LABEL),
        stored_presignature_before
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
async fn cluster__should_sign_from_stored_presignatures_when_online_presign_is_disabled() {
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
        port_seed::ONLINE_PRESIGN_DISABLED_TEST,
        DEFAULT_BLOCK_TIME,
    );
    for node in &mut setup.configs {
        node.config.signature.online_presign = false;
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
        contract.add_domains(vec![domain.clone()]);
    }
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
    wait_until_positive(&MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE, "presignatures").await;
    let stored_presignature_before = signatures_led(STORED_PRESIGNATURE_MODE_LABEL);
    let online_presign_before = signatures_led(ONLINE_PRESIGN_MODE_LABEL);

    // When
    for user in ["user0", "user1", "user2"] {
        assert!(
            request_signature_and_await_response(
                &mut setup.indexer,
                user,
                &domain,
                DEFAULT_MAX_SIGNATURE_WAIT_TIME,
            )
            .await
            .is_some()
        );
    }

    // Then
    assert!(signatures_led(STORED_PRESIGNATURE_MODE_LABEL) > stored_presignature_before);
    assert_eq!(
        signatures_led(ONLINE_PRESIGN_MODE_LABEL),
        online_presign_before
    );
}
