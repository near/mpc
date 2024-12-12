use std::collections::{HashMap, HashSet};

use crate::cli::Cli;
use crate::tracking::AutoAbortTask;
use near_o11y::testonly::init_integration_logger;
use rand::Rng;
use serial_test::serial;

// Make a cluster of four nodes. Test the following:
// 1. Shut down one node and confirms that signatures can still be generated.
// 2. Stop another node and assert that no signatures can be generated.
// 3. Restart the node that was later shutdown and assert that signatures can be generated again
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_faulty_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    let temp_dir = tempfile::tempdir().unwrap();
    let generate_configs = Cli::GenerateTestConfigs {
        output_dir: temp_dir.path().to_str().unwrap().to_string(),
        num_participants: NUM_PARTICIPANTS,
        threshold: THRESHOLD,
        seed: Some(2),
        disable_indexer: true,
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

    // Give it some time for the ports to be released.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // We'll bring up the nodes in normal mode, and issue signature
    // requests, and check that they can be completed.
    let mut normal_runs = (0..NUM_PARTICIPANTS)
        .map(|i| {
            let home_dir = temp_dir.path().join(format!("{}", i));
            let cli = Cli::Start {
                home_dir: home_dir.to_str().unwrap().to_string(),
                secret_store_key_hex: hex::encode(encryption_keys[i]),
                p2p_private_key: None,
                root_keyshare: None,
            };
            (i, AutoAbortTask::from(tokio::spawn(cli.run())))
        })
        .collect::<HashMap<_, _>>();

    // First ask the nodes to "index" the signature requests

    let mut retries_left = 20;
    'outer: for i in 0..NUM_PARTICIPANTS {
        while retries_left > 0 {
            let url = format!(
                "http://{}:{}/debug/index?msg=hello&repeat=1&seed=23",
                "127.0.0.1",
                22000 + i
            );
            let response = match reqwest::get(&url).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!("Failed to get response from node {}: {}", i, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
            let response_success = response.status().is_success();
            let response_debug = format!("{:?}", response);
            let response_text = response.text().await.unwrap_or_default();
            if !response_success {
                tracing::error!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    i,
                    response_debug,
                    response_text
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                retries_left -= 1;
            } else {
                tracing::info!("Got response from node {}: {}", i, response_text);
                continue 'outer;
            }
        }
        panic!("Failed to get response from node {}", i);
    }

    tracing::info!("Requests indexed");

    // First step: drop one node, and make sure we can still get a signature.

    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..NUM_PARTICIPANTS);
    let to_drop = normal_runs.remove(&index).unwrap();
    drop(to_drop);
    let mut dropped_indices = HashSet::new();
    dropped_indices.insert(index);

    let mut signature_generated = false;
    'outer: for _ in 0..2 {
        for i in 0..NUM_PARTICIPANTS {
            let url = format!(
                "http://{}:{}/debug/sign?repeat=1&seed=23",
                "127.0.0.1",
                22000 + i
            );
            let response = match reqwest::get(&url).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!("Failed to get response from node {}: {}", i, e);
                    continue;
                }
            };
            let response_success = response.status().is_success();
            let response_debug = format!("{:?}", response);
            let response_text = response.text().await.unwrap_or_default();
            if !response_success {
                tracing::error!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    i,
                    response_debug,
                    response_text
                );
            } else {
                tracing::info!("Got response from node {}: {}", i, response_text);
                signature_generated = true;
                break 'outer;
            }
        }
    }

    if !signature_generated {
        panic!("Failed to get response from any node");
    }

    tracing::info!("Step 1 complete");

    // Second step: drop another node, and make sure signatures cannot be generated

    let another_index = loop {
        let i = rng.gen_range(0..NUM_PARTICIPANTS);
        if !dropped_indices.contains(&i) {
            break i;
        }
    };
    drop(normal_runs.remove(&another_index).unwrap());
    dropped_indices.insert(another_index);

    let index = loop {
        let i = rng.gen_range(0..NUM_PARTICIPANTS);
        if !dropped_indices.contains(&i) {
            break i;
        }
    };

    let url = format!(
        "http://{}:{}/debug/sign?repeat=1&seed=23",
        "127.0.0.1",
        22000 + index
    );
    match reqwest::get(&url).await {
        Ok(response) => {
            let response_success = response.status().is_success();
            let response_debug = format!("{:?}", response);
            let response_text = response.text().await.unwrap_or_default();
            if !response_success {
                tracing::info!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    index,
                    response_debug,
                    response_text
                );
            } else {
                panic!(
                    "Got response from node {} unexpectedly: {}",
                    index, response_text
                );
            }
        }
        Err(e) => {
            tracing::info!("Failed to get response from node {}: {}", index, e);
        }
    };

    tracing::info!("Step 2 complete");

    // Third step: bring up the dropped node in step 2, and make sure signatures can be generated again

    let task = AutoAbortTask::from(tokio::spawn(async move {
        let home_dir = temp_dir.path().join(format!("{}", another_index));
        let cli = Cli::Start {
            home_dir: home_dir.to_str().unwrap().to_string(),
            secret_store_key_hex: hex::encode(encryption_keys[another_index]),
            p2p_private_key: None,
            root_keyshare: None,
        };
        cli.run().await.unwrap();
    }));
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    let url = format!(
        "http://{}:{}/debug/sign?repeat=1&seed=23",
        "127.0.0.1",
        22000 + another_index
    );
    match reqwest::get(&url).await {
        Ok(response) => {
            let response_success = response.status().is_success();
            let response_debug = format!("{:?}", response);
            let response_text = response.text().await.unwrap_or_default();
            if !response_success {
                panic!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    another_index, response_debug, response_text
                );
            }
        }
        Err(e) => {
            panic!("Failed to get response from node {}: {}", another_index, e);
        }
    };

    tracing::info!("Step 3 complete");

    drop(task);
    drop(normal_runs);
}
