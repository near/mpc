use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_ckd_and_await_response, request_signature_and_await_response, IntegrationTestSetup,
    DEFAULT_BLOCK_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
async fn test_basic_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::BASIC_CLUSTER_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let signature_domain_ecdsa = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    let signature_domain_eddsa = DomainConfig {
        id: DomainId(1),
        scheme: SignatureScheme::Ed25519,
    };

    let ckd_domain = DomainConfig {
        id: DomainId(2),
        scheme: SignatureScheme::Bls12381,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![
            signature_domain_ecdsa.clone(),
            signature_domain_eddsa.clone(),
            ckd_domain.clone(),
        ]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &signature_domain_ecdsa,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &signature_domain_eddsa,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    assert!(request_ckd_and_await_response(
        &mut setup.indexer,
        "user0",
        &ckd_domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}
