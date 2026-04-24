use crate::common;

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::{BackupServiceInfo, DestinationNodeInfo, ParticipantInfo};

/// Per-account migration entry: (backup_service_info, destination_node_info).
type AccountEntry = (Option<BackupServiceInfo>, Option<DestinationNodeInfo>);

/// Full migration state as returned by the contract's `migration_info` view.
type MigrationState = BTreeMap<String, AccountEntry>;

/// Verify the `/debug/migrations` endpoint tracks migration state in lockstep
/// with the contract. The scenario is a chain of Given/When/Then steps:
///
/// 1. Given a fresh cluster → Then migration state is empty on both sides.
/// 2. When a backup service is registered → Then contract + endpoint reflect it.
/// 3. When node migration is started → Then contract + endpoint reflect the
///    destination entry.
///
/// The chain is replayed for every node so each registration builds on the
/// prior node's final state.
#[tokio::test]
#[expect(non_snake_case)]
async fn migration_endpoint__should_track_migration_state() {
    // Given: a fresh cluster with no migration state.
    let (cluster, _running) = common::setup_cluster(common::MIGRATION_ENDPOINT_PORT_SEED, |_| {})
        .await
        .expect("setup_cluster failed");

    let client = reqwest::Client::new();
    let mut expected_migrations = MigrationState::new();

    for (i, node_state) in cluster.nodes.iter().enumerate() {
        let node = match node_state {
            MpcNodeState::Running(n) => n,
            _ => panic!("node {i} is not running"),
        };
        let web_addr = node.web_address();
        let account_id = node_state.account_id().to_string();
        let p2p_public_key = node_state.p2p_public_key_str();

        // Given: the migration state carried over from prior iterations
        //         (empty on the first iteration).
        // Then: contract and endpoint already match that carried state.
        assert_contract_matches(&cluster, &expected_migrations)
            .await
            .expect("contract state mismatch");
        assert_endpoint_matches(&client, &web_addr, &expected_migrations)
            .await
            .expect("endpoint state mismatch");

        // When: register a bogus backup service for this node.
        let backup_service_info = serde_json::json!({ "public_key": p2p_public_key });
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

        // Then: contract and endpoint both expose the backup registration.
        assert_contract_matches(&cluster, &expected_migrations)
            .await
            .expect("contract state mismatch after backup registration");
        assert_endpoint_matches(&client, &web_addr, &expected_migrations)
            .await
            .expect("endpoint state mismatch after backup registration");

        // When: start node migration with a bogus destination.
        let destination_node_info = serde_json::json!({
            "signer_account_pk": p2p_public_key,
            "destination_node_info": {
                "url": "http://bogus:1234",
                "tls_public_key": p2p_public_key,
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
                tls_public_key: node_state.p2p_public_key(),
            },
        };
        expected_migrations.insert(account_id, (Some(backup_info), Some(dest_info)));

        // Then: contract and endpoint both expose the destination entry.
        assert_contract_matches(&cluster, &expected_migrations)
            .await
            .expect("contract state mismatch after start_node_migration");
        assert_endpoint_matches(&client, &web_addr, &expected_migrations)
            .await
            .expect("endpoint state mismatch after start_node_migration");
    }
}

async fn get_contract_migrations(
    cluster: &e2e_tests::MpcCluster,
) -> anyhow::Result<MigrationState> {
    cluster
        .view_migration_info::<MigrationState>()
        .await
        .context("failed to view migration info")
}

async fn get_debug_migrations(
    client: &reqwest::Client,
    web_addr: &str,
) -> anyhow::Result<(u64, MigrationState)> {
    let resp = client
        .get(format!("http://{web_addr}/debug/migrations"))
        .send()
        .await
        .context("failed to fetch /debug/migrations")?;
    let status = resp.status();
    if status != reqwest::StatusCode::OK {
        bail!("unexpected /debug/migrations status: {status}");
    }
    resp.json::<(u64, MigrationState)>()
        .await
        .context("failed to parse migration response")
}

/// Assert the contract's migration state eventually equals `expected`.
/// Retries to absorb indexer lag, then returns an error on timeout.
async fn assert_contract_matches(
    cluster: &e2e_tests::MpcCluster,
    expected: &MigrationState,
) -> anyhow::Result<()> {
    let expected = expected.clone();
    (|| async {
        let actual = get_contract_migrations(cluster).await?;
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
    .context("timed out waiting for contract migration state to match")
}

/// Assert the node's `/debug/migrations` endpoint eventually equals `expected`.
/// Retries to absorb indexer lag, then returns an error on timeout.
async fn assert_endpoint_matches(
    client: &reqwest::Client,
    web_addr: &str,
    expected: &MigrationState,
) -> anyhow::Result<()> {
    let expected = expected.clone();
    (|| async {
        let (_, actual) = get_debug_migrations(client, web_addr).await?;
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
    .context("timed out waiting for debug endpoint migration state to match")
}
