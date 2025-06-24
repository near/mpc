use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{request_signature_and_await_response, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_sdk::AccountId;
use near_time::Clock;
use rand::Rng;
use serial_test::serial;

// Make a cluster of four nodes. Test the following:
// 1. Shut down one node and confirms that signatures can still be generated.
// 2. Stop another node and assert that no signatures can be generated.
// 3. Restart the node that was later shutdown and assert that signatures can be generated again
#[tokio::test]
#[serial]
async fn test_faulty_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let accounts = (0..NUM_PARTICIPANTS)
        .map(|i| format!("test{}", i).parse().unwrap())
        .collect::<Vec<AccountId>>();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        accounts.clone(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::FAULTY_CLUSTER_TEST,
    );

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants);
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    tracing::info!("Waiting for key generation to complete");
    setup
        .indexer
        .wait_for_contract_state(|state| matches!(state, ContractState::Running(_)))
        .await;
    tracing::info!("Key generation complete");

    let Some(signature_delay) = request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60),
    )
    .await
    else {
        panic!("Timed out generating the first signature");
    };

    // first step: drop one node, and make sure signatures can still be generated
    let mut rng = rand::thread_rng();
    let to_drop: usize = rng.gen_range(0..NUM_PARTICIPANTS);
    tracing::info!("Bringing down one node #{}", to_drop);
    let disabled1 = setup.indexer.disable(accounts[to_drop].clone()).await;

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        signature_delay * 2
    )
    .await
    .is_some());
    tracing::info!("Step 1 complete");

    // Second step: drop another node, and make sure signatures cannot be generated
    let another_to_drop = loop {
        let i = rng.gen_range(0..NUM_PARTICIPANTS);
        if i != to_drop {
            break i;
        }
    };
    tracing::info!("Bringing down another node #{}", another_to_drop);
    let disabled2 = setup
        .indexer
        .disable(accounts[another_to_drop].clone())
        .await;
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user2",
        &domain,
        signature_delay * 2
    )
    .await
    .is_none());
    tracing::info!("Step 2 complete");

    // Third step: bring up the dropped node in step 2, and make sure signatures can be generated again
    disabled2.reenable_and_wait_till_running().await;
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user3",
        &domain,
        signature_delay * 2
    )
    .await
    .is_some());
    tracing::info!("Step 3 complete");

    drop(disabled1);

    // Pausing just one node should lead to signature request failures.
    // We have 3 nodes online with threshold of 3.
    tracing::info!("Pausing node #0");
    let paused1 = setup.indexer.pause_indexer(accounts[0].clone()).await;
    // tracing::info!("Pausing node #1");
    // let paused2 = setup.indexer.pause_indexer(accounts[1].clone()).await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    const REQUESTS: u8 = 10;
    let mut successful_requests = 0;

    for _ in 0..REQUESTS {
        let request = request_signature_and_await_response(
            &mut setup.indexer,
            "user2",
            &domain,
            signature_delay * 2,
        )
        .await;

        if request.is_some() {
            successful_requests += 1;
        }
    }

    assert_eq!(
        successful_requests, REQUESTS,
        "Expected all requests to complete."
    );
    tracing::info!("Step 4 complete");
    drop(paused1);

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user3",
        &domain,
        signature_delay * 2
    )
    .await
    .is_some());
    tracing::info!("Step 5 complete");
}
