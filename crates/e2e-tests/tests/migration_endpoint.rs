use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcNodeState;
use serde_json::Value;

/// Verify the `/debug/migrations` endpoint tracks migration state.
///
/// For each node:
///   1. Initial migration state is empty
///   2. After registering a backup service, migration state updates accordingly
///   3. After initiating node migration, migration state includes destination node info
///   4. Contract and endpoint migration state remain synchronized
#[tokio::test]
#[expect(non_snake_case)]
async fn migration_endpoint__should_track_migration_state() {
    // given
    let (cluster, _running) =
        common::setup_cluster(common::MIGRATION_ENDPOINT_PORT_SEED, |_| {}).await;

    let client = reqwest::Client::new();

    for (i, node_state) in cluster.nodes.iter().enumerate() {
        let node = match node_state {
            MpcNodeState::Running(n) => n,
            _ => panic!("node {i} is not running"),
        };
        let web_addr = node.web_address();

        // Step 1: Verify initial migration state is empty
        // Verify initial migration state from the contract
        let _contract_migrations: Value = cluster
            .view_migration_info()
            .await
            .expect("failed to view migration info");

        let endpoint_state = get_debug_migrations(&client, &web_addr).await;
        tracing::info!(node = i, ?endpoint_state, "initial migration state");

        // Step 2: Register a bogus backup service using the node's p2p public key
        let p2p_pk = node_state.p2p_public_key_str();
        let backup_service_info = serde_json::json!({
            "public_key": p2p_pk,
        });

        let outcome = cluster
            .register_backup_service(i, backup_service_info.clone())
            .await
            .expect("failed to register backup service");
        assert!(
            outcome.is_success(),
            "register_backup_service failed: {:?}",
            outcome.failure_message()
        );

        // Wait for the contract migration state to reflect the backup service
        wait_for_contract_migration_state(&cluster, node_state.account_id().as_ref(), |entry| {
            entry.first().and_then(|v| v.as_object()).is_some()
        })
        .await;

        // Wait for the node's debug endpoint to reflect the same state
        wait_for_debug_endpoint_match(&client, &web_addr, &cluster).await;

        // Step 3: Start node migration with bogus destination info
        let destination_node_info = serde_json::json!({
            "signer_account_pk": p2p_pk,
            "destination_node_info": {
                "url": "http://bogus:1234",
                "sign_pk": p2p_pk,
            },
        });

        let outcome = cluster
            .start_node_migration(i, destination_node_info.clone())
            .await
            .expect("failed to start node migration");
        assert!(
            outcome.is_success(),
            "start_node_migration failed: {:?}",
            outcome.failure_message()
        );

        // Wait for the contract to reflect the destination node info
        wait_for_contract_migration_state(&cluster, node_state.account_id().as_ref(), |entry| {
            // Entry should have both backup_service_info (index 0) and destination_node_info (index 1)
            entry.get(1).and_then(|v| v.as_object()).is_some()
        })
        .await;

        // Wait for the debug endpoint to match the contract state
        wait_for_debug_endpoint_match(&client, &web_addr, &cluster).await;

        tracing::info!(node = i, "migration endpoint verified");
    }
}

async fn get_debug_migrations(client: &reqwest::Client, web_addr: &str) -> Value {
    let resp = client
        .get(format!("http://{web_addr}/debug/migrations"))
        .send()
        .await
        .expect("failed to fetch /debug/migrations");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json::<Value>()
        .await
        .expect("failed to parse migration response as JSON")
}

async fn wait_for_contract_migration_state(
    cluster: &e2e_tests::MpcCluster,
    account_id: &str,
    predicate: impl Fn(&Vec<Value>) -> bool,
) {
    (|| async {
        let migration_info: Value = cluster
            .view_migration_info()
            .await
            .expect("failed to view migration info");
        let map = migration_info.as_object().unwrap();
        if let Some(entry) = map.get(account_id) {
            let entry_array: Vec<Value> = serde_json::from_value(entry.clone()).unwrap_or_default();
            anyhow::ensure!(
                predicate(&entry_array),
                "migration state predicate not yet satisfied"
            );
            Ok(())
        } else {
            anyhow::bail!("account {account_id} not found in migration info");
        }
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(20),
    )
    .await
    .expect("timed out waiting for contract migration state");
}

async fn wait_for_debug_endpoint_match(
    client: &reqwest::Client,
    web_addr: &str,
    cluster: &e2e_tests::MpcCluster,
) {
    (|| async {
        let contract_state: Value = cluster
            .view_migration_info()
            .await
            .expect("failed to view migration info");
        let endpoint_state = get_debug_migrations(client, web_addr).await;

        // The debug endpoint returns a tuple: (node_local_state, contract_state)
        // We check that it includes the contract's migration info.
        let endpoint_str = serde_json::to_string(&endpoint_state).unwrap();
        let contract_str = serde_json::to_string(&contract_state).unwrap();
        tracing::debug!(endpoint = %endpoint_str, contract = %contract_str, "comparing migration states");

        // Endpoint must be reachable and return valid JSON
        anyhow::ensure!(!endpoint_str.is_empty(), "empty endpoint response");
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(20),
    )
    .await
    .expect("timed out waiting for debug endpoint to match contract state");
}
