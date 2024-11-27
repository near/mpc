use crate::cli::Cli;
use crate::tracking::AutoAbortTask;
use near_o11y::testonly::init_integration_logger;
use serial_test::serial;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_basic_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    let temp_dir = tempfile::tempdir().unwrap();
    let generate_configs = Cli::GenerateTestConfigs {
        output_dir: temp_dir.path().to_str().unwrap().to_string(),
        num_participants: NUM_PARTICIPANTS,
        threshold: THRESHOLD,
    };
    generate_configs.run().await.unwrap();

    let encryption_keys = (0..NUM_PARTICIPANTS)
        .map(|_| rand::random::<[u8; 16]>())
        .collect::<Vec<_>>();

    // First, generate keys. All nodes run key generation until they exit.
    let key_generation_runs = (0..NUM_PARTICIPANTS)
        .map(|i| {
            let home_dir = temp_dir.path().join(format!("{}", i));
            let cli = Cli::GenerateKey {
                home_dir: home_dir.to_str().unwrap().to_string(),
                secret_store_key_hex: hex::encode(encryption_keys[i]),
            };
            cli.run()
        })
        .collect::<Vec<_>>();

    futures::future::try_join_all(key_generation_runs)
        .await
        .unwrap();

    tracing::info!("Key generation complete. Starting normal runs...");

    // We'll bring up the nodes in normal mode, and issue signature
    // requests, and check that they can be completed.
    let normal_runs = (0..NUM_PARTICIPANTS)
        .map(|i| {
            let home_dir = temp_dir.path().join(format!("{}", i));
            let cli = Cli::Start {
                home_dir: home_dir.to_str().unwrap().to_string(),
                secret_store_key_hex: hex::encode(encryption_keys[i]),
            };
            AutoAbortTask::from(tokio::spawn(cli.run()))
        })
        .collect::<Vec<_>>();

    // Give servers some time to start up.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    for i in 0..NUM_PARTICIPANTS {
        let url = format!(
            "http://{}:{}/debug/sign?msg=hello&repeat=10",
            "127.0.0.1",
            20000 + i
        );
        let response = reqwest::get(&url).await.unwrap();
        assert!(
            response.status().is_success(),
            "Failed to get {}: {:?}",
            url,
            response
        );
    }

    drop(normal_runs);
}
