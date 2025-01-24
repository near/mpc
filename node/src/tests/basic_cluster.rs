use crate::indexer::handler::{ChainSignatureRequest, SignArgs};
use crate::tests::generate_test_configs_with_fake_indexer;
use crate::tracking::AutoAbortTask;
use k256::elliptic_curve::Field;
use k256::Scalar;
use near_o11y::testonly::init_integration_logger;
use near_time::{Clock, Duration};
use serial_test::serial;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
#[serial]
async fn test_basic_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY: Duration = Duration::seconds(3);
    const PORT_SEED: u16 = 2;
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut indexer, configs) = generate_test_configs_with_fake_indexer(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY,
        PORT_SEED,
    );

    let _runs = configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    indexer.request_signature(ChainSignatureRequest {
        entropy: rand::random(),
        request_id: rand::random(),
        predecessor_id: "user0".parse().unwrap(),
        timestamp_nanosec: rand::random(),
        request: SignArgs {
            key_version: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            payload: Scalar::random(&mut rand::thread_rng()),
        },
    });
    let response = indexer.next_response().await;
    tracing::info!("Response: {:?}", response);
}
