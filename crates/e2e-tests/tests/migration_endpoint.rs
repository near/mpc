use crate::common;

use std::collections::BTreeMap;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::{BackupServiceInfo, DestinationNodeInfo, ParticipantInfo};

/// Per-account migration entry: (backup_service_info, destination_node_info).
type AccountEntry = (Option<BackupServiceInfo>, Option<DestinationNodeInfo>);

/// Full migration state as returned by the contract's `migration_info` view.
type MigrationState = BTreeMap<String, AccountEntry>;

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
    let mut expected_migrations = MigrationState::new();

    for (i, node_state) in cluster.nodes.iter().enumerate() {
        let node = match node_state {
            MpcNodeState::Running(n) => n,
            _ => panic!("node {i} is not running"),
        };
        let web_addr = node.web_address();
        let account_id = node_state.account_id().to_string();

        // Step 1: Verify migration state matches expected (poll because each
        // node's indexer may lag behind contract changes from prior iterations)
        wait_for_contract_match(&cluster, &expected_migrations).await;
        wait_for_endpoint_match(&client, &web_addr, &expected_migrations).await;

        // Step 2: Register a bogus backup service using the node's p2p public key
        let p2p_public_key = node_state.p2p_public_key_str();
        let backup_service_info = serde_json::json!({
            "public_key": p2p_public_key,
        });

        let outcome = cluster
            .register_backup_service(i, backup_service_info)
            .await
            .expect("failed to register backup service");
        assert!(
            outcome.is_success(),
            "register_backup_service failed: {:?}",
            outcome.failure_message()
        );

        let backup_info = BackupServiceInfo {
            public_key: node_state.p2p_public_key(),
        };
        expected_migrations.insert(account_id.clone(), (Some(backup_info.clone()), None));

        // Wait for contract to match expected state
        wait_for_contract_match(&cluster, &expected_migrations).await;
        // Wait for debug endpoint to match expected state
        wait_for_endpoint_match(&client, &web_addr, &expected_migrations).await;

        // Step 3: Start node migration with bogus destination info
        let destination_node_info = serde_json::json!({
            "signer_account_pk": p2p_public_key,
            "destination_node_info": {
                "url": "http://bogus:1234",
                "sign_pk": p2p_public_key,
            },
        });

        let outcome = cluster
            .start_node_migration(i, destination_node_info)
            .await
            .expect("failed to start node migration");
        assert!(
            outcome.is_success(),
            "start_node_migration failed: {:?}",
            outcome.failure_message()
        );

        let dest_info = DestinationNodeInfo {
            signer_account_pk: node_state.p2p_public_key(),
            destination_node_info: ParticipantInfo {
                url: "http://bogus:1234".to_string(),
                sign_pk: node_state.p2p_public_key(),
            },
        };
        expected_migrations.insert(account_id.clone(), (Some(backup_info), Some(dest_info)));

        // Wait for contract to match expected state
        wait_for_contract_match(&cluster, &expected_migrations).await;
        // Wait for debug endpoint to match expected state
        wait_for_endpoint_match(&client, &web_addr, &expected_migrations).await;

        tracing::info!(node = i, "migration endpoint verified");
    }
}

async fn get_contract_migrations(cluster: &e2e_tests::MpcCluster) -> MigrationState {
    cluster
        .view_migration_info::<MigrationState>()
        .await
        .expect("failed to view migration info")
}

async fn get_debug_migrations(client: &reqwest::Client, web_addr: &str) -> (u64, MigrationState) {
    let resp = client
        .get(format!("http://{web_addr}/debug/migrations"))
        .send()
        .await
        .expect("failed to fetch /debug/migrations");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json::<(u64, MigrationState)>()
        .await
        .expect("failed to parse migration response")
}

async fn wait_for_contract_match(cluster: &e2e_tests::MpcCluster, expected: &MigrationState) {
    let expected = expected.clone();
    (|| async {
        let actual = get_contract_migrations(cluster).await;
        anyhow::ensure!(
            actual == expected,
            "contract migration state mismatch: expected {expected:?}, got {actual:?}"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(20),
    )
    .await
    .expect("timed out waiting for contract migration state to match");
}

async fn wait_for_endpoint_match(
    client: &reqwest::Client,
    web_addr: &str,
    expected: &MigrationState,
) {
    let expected = expected.clone();
    (|| async {
        let (_, actual) = get_debug_migrations(client, web_addr).await;
        anyhow::ensure!(
            actual == expected,
            "endpoint migration state mismatch: expected {expected:?}, got {actual:?}"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(20),
    )
    .await
    .expect("timed out waiting for debug endpoint migration state to match");
}
