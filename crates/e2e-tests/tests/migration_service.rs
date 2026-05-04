use crate::common;

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, bail};
use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::ProtocolContractState;
use rand::SeedableRng;

const MIGRATION_PORT_TIMEOUT: Duration = Duration::from_secs(120);
const INDEXER_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
const MIGRATION_COMPLETION_TIMEOUT: Duration = Duration::from_secs(60);

struct BackupService {
    home_dir: tempfile::TempDir,
    binary_path: PathBuf,
}

impl BackupService {
    fn must_get_new(binary_path: PathBuf) -> Self {
        Self {
            home_dir: tempfile::tempdir().expect("failed to create backup service home dir"),
            binary_path,
        }
    }

    fn must_get_home_dir_str(&self) -> &str {
        self.home_dir
            .path()
            .to_str()
            .expect("backup service home dir path is not valid UTF-8")
    }

    fn must_generate_keys(&self) {
        let output = Command::new(&self.binary_path)
            .args(["--home-dir", self.must_get_home_dir_str(), "generate-keys"])
            .output()
            .expect("failed to run backup-cli generate-keys");
        assert!(
            output.status.success(),
            "backup-cli generate-keys failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn public_key(&self) -> anyhow::Result<String> {
        let secrets_path = self.home_dir.path().join("secrets.json");
        let contents = std::fs::read_to_string(&secrets_path)
            .with_context(|| format!("failed to read {}", secrets_path.display()))?;
        let secrets: serde_json::Value =
            serde_json::from_str(&contents).context("failed to parse secrets.json")?;
        let p2p_key_bytes: Vec<u8> = serde_json::from_value(secrets["p2p_private_key"].clone())
            .context("failed to parse p2p_private_key")?;
        let secret_bytes: [u8; 32] = p2p_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 bytes for signing key"))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let public_key =
            near_mpc_crypto_types::Ed25519PublicKey::from(&signing_key.verifying_key());
        Ok(String::from(&public_key))
    }

    fn set_contract_state(&self, state: &ProtocolContractState) -> anyhow::Result<()> {
        let state_path = self.home_dir.path().join("contract_state.json");
        let json =
            serde_json::to_string_pretty(state).context("failed to serialize contract state")?;
        std::fs::write(&state_path, json)
            .with_context(|| format!("failed to write {}", state_path.display()))?;
        Ok(())
    }

    fn get_keyshares(
        &self,
        node_migration_address: &str,
        node_p2p_key: &str,
        backup_encryption_key_hex: &str,
    ) -> anyhow::Result<()> {
        let output = Command::new(&self.binary_path)
            .args([
                "--home-dir",
                self.must_get_home_dir_str(),
                "get-keyshares",
                "--mpc-node-address",
                node_migration_address,
                "--mpc-node-p2p-key",
                node_p2p_key,
                "--backup-encryption-key-hex",
                backup_encryption_key_hex,
            ])
            .output()
            .context("failed to run backup-cli get-keyshares")?;
        anyhow::ensure!(
            output.status.success(),
            "backup-cli get-keyshares failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    fn put_keyshares(
        &self,
        node_migration_address: &str,
        node_p2p_key: &str,
        backup_encryption_key_hex: &str,
    ) -> anyhow::Result<()> {
        let output = Command::new(&self.binary_path)
            .args([
                "--home-dir",
                self.must_get_home_dir_str(),
                "put-keyshares",
                "--mpc-node-address",
                node_migration_address,
                "--mpc-node-p2p-key",
                node_p2p_key,
                "--backup-encryption-key-hex",
                backup_encryption_key_hex,
            ])
            .output()
            .context("failed to run backup-cli put-keyshares")?;
        anyhow::ensure!(
            output.status.success(),
            "backup-cli put-keyshares failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}

/// Resolve the backup-cli binary path. Built by `cargo make e2e-tests`
/// (see `build-backup-cli` task in Makefile.toml).
///
/// Plumbing helper: a missing binary means the test wasn't built correctly,
/// not that the system under test failed, so we panic.
fn must_get_backup_cli_path() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/backup-cli");
    assert!(
        path.exists(),
        "backup-cli binary not found at {}. Run `cargo make e2e-tests` to build it.",
        path.display()
    );
    path
}

async fn wait_for_migration_port(address: &str) -> anyhow::Result<()> {
    let timeout = MIGRATION_PORT_TIMEOUT;
    (|| async {
        let result = std::net::TcpStream::connect(address);
        anyhow::ensure!(
            result.is_ok(),
            "migration port not yet listening at {address}"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times((timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize),
    )
    .await
    .with_context(|| format!("migration port {address} never became reachable"))
}

fn running_state_matches_participant_key(
    state: &ProtocolContractState,
    account_id: &str,
    expected_pk: &str,
) -> bool {
    match state {
        ProtocolContractState::Running(r) => {
            r.parameters
                .participants
                .participants
                .iter()
                .any(|(a, _, info)| {
                    a.as_str() == account_id && String::from(&info.tls_public_key) == expected_pk
                })
        }
        _ => false,
    }
}

/// Register a backup service for the source node and wait for both the
/// contract and the source node's debug endpoint to reflect the registration.
async fn register_backup_service_and_wait(
    cluster: &e2e_tests::MpcCluster,
    source_idx: usize,
    backup_service: &BackupService,
) -> anyhow::Result<()> {
    let backup_public_key = backup_service.public_key()?;
    let source_account_id = cluster.nodes[source_idx].account_id().to_string();

    let outcome = cluster
        .register_backup_service(
            source_idx,
            serde_json::json!({ "public_key": backup_public_key }),
        )
        .await
        .context("failed to register backup service")?;
    anyhow::ensure!(
        outcome.is_success(),
        "register_backup_service failed: {:?}",
        outcome.failure_message()
    );

    (|| async {
        let info: serde_json::Value = cluster
            .view_migration_info()
            .await
            .context("failed to view migration info")?;
        let entry = info.get(&source_account_id);
        anyhow::ensure!(
            entry.is_some_and(|e| !e.get(0).unwrap_or(&serde_json::Value::Null).is_null()),
            "node has not indexed backup registration yet"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (INDEXER_SYNC_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .context("timed out waiting for node to index backup registration")?;

    let source_web_addr = match &cluster.nodes[source_idx] {
        MpcNodeState::Running(n) => n.web_address(),
        _ => bail!("source node not running"),
    };
    let http_client = reqwest::Client::new();
    (|| async {
        let resp = http_client
            .get(format!("http://{source_web_addr}/debug/migrations"))
            .send()
            .await?;
        let body = resp.text().await?;
        anyhow::ensure!(
            body.contains(&backup_public_key),
            "node debug endpoint doesn't reflect backup registration yet"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (INDEXER_SYNC_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .context("timed out waiting for node debug endpoint to show backup registration")?;

    Ok(())
}

/// GET keyshares from the source node via the backup CLI.
async fn get_keyshares_from_source(
    cluster: &e2e_tests::MpcCluster,
    source_idx: usize,
    backup_service: &BackupService,
) -> anyhow::Result<()> {
    let contract_state = cluster
        .get_contract_state()
        .await
        .context("failed to get contract state")?;
    backup_service.set_contract_state(&contract_state)?;

    let source_migration_addr = match &cluster.nodes[source_idx] {
        MpcNodeState::Running(n) => n.migration_web_ui_address(),
        _ => bail!("source node not running"),
    };
    let source_p2p_key = cluster.nodes[source_idx].p2p_public_key_str();
    wait_for_migration_port(&source_migration_addr).await?;
    backup_service.get_keyshares(
        &source_migration_addr,
        &source_p2p_key,
        cluster.nodes[source_idx].backup_encryption_key_hex(),
    )
}

/// Start node migration on the contract and wait for confirmation.
async fn start_migration_and_wait(
    cluster: &e2e_tests::MpcCluster,
    source_idx: usize,
    target_idx: usize,
) -> anyhow::Result<()> {
    let source_account_id = cluster.nodes[source_idx].account_id().to_string();
    let target_p2p_key = cluster.nodes[target_idx].p2p_public_key_str();
    let target_p2p_url = cluster.nodes[target_idx].p2p_url();
    let target_signer_pk = cluster.nodes[target_idx].near_signer_public_key_str();

    let destination_node_info = serde_json::json!({
        "signer_account_pk": target_signer_pk,
        "destination_node_info": {
            "url": target_p2p_url,
            "tls_public_key": target_p2p_key,
        },
    });
    let outcome = cluster
        .start_node_migration(source_idx, destination_node_info)
        .await
        .context("failed to start node migration")?;
    anyhow::ensure!(
        outcome.is_success(),
        "start_node_migration failed: {:?}",
        outcome.failure_message()
    );

    (|| async {
        let info: serde_json::Value = cluster
            .view_migration_info()
            .await
            .context("failed to view migration info")?;
        let entry = info.get(&source_account_id);
        anyhow::ensure!(
            entry.is_some_and(|e| !e.get(1).unwrap_or(&serde_json::Value::Null).is_null()),
            "contract has not indexed node migration yet"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (INDEXER_SYNC_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .context("timed out waiting for contract to reflect node migration")
}

/// PUT keyshares to the target node via the backup CLI.
async fn put_keyshares_to_target(
    cluster: &e2e_tests::MpcCluster,
    target_idx: usize,
    backup_service: &BackupService,
) -> anyhow::Result<()> {
    let target_migration_addr = match &cluster.nodes[target_idx] {
        MpcNodeState::Running(n) => n.migration_web_ui_address(),
        _ => bail!("target node not running"),
    };
    wait_for_migration_port(&target_migration_addr).await?;

    let contract_state = cluster
        .get_contract_state()
        .await
        .context("failed to get contract state")?;
    backup_service.set_contract_state(&contract_state)?;

    let target_p2p_key = cluster.nodes[target_idx].p2p_public_key_str();
    backup_service.put_keyshares(
        &target_migration_addr,
        &target_p2p_key,
        cluster.nodes[target_idx].backup_encryption_key_hex(),
    )
}

/// Wait for the target to become an active participant and for migration
/// state to clear from the contract.
async fn wait_for_migration_completion(
    cluster: &e2e_tests::MpcCluster,
    source_idx: usize,
    target_idx: usize,
) -> anyhow::Result<()> {
    let source_account_id = cluster.nodes[source_idx].account_id().to_string();
    let target_p2p_key = cluster.nodes[target_idx].p2p_public_key_str();

    (|| async {
        let state = cluster
            .get_contract_state()
            .await
            .context("failed to get contract state")?;
        anyhow::ensure!(
            running_state_matches_participant_key(&state, &source_account_id, &target_p2p_key),
            "target node not yet active participant"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (MIGRATION_COMPLETION_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis())
                    as usize,
            ),
    )
    .await
    .context("timed out waiting for migration to complete")?;

    (|| async {
        let migration_info: serde_json::Value = cluster
            .view_migration_info()
            .await
            .context("failed to view migration info")?;
        let entry = migration_info
            .get(&source_account_id)
            .context("account not found in migration info")?;
        let destination = entry.get(1).unwrap_or(&serde_json::Value::Null);
        anyhow::ensure!(
            destination.is_null(),
            "migration destination should be cleared after completion"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(20),
    )
    .await
    .context("migration state did not clear")
}

/// Full end-to-end node migration via the backup CLI.
///
/// Starts a cluster with 2 participating nodes and 2 target nodes (started
/// upfront so their indexers have time to sync). For each participating node:
///   1. Register backup service
///   2. GET keyshares from source node
///   3. Initiate node migration
///   4. PUT keyshares to target node
///   5. Verify target node becomes active participant
///   6. Kill old node and verify sign requests succeed
#[tokio::test]
#[expect(non_snake_case)]
async fn migration_service__should_migrate_nodes_via_backup_cli() {
    let backup_cli = must_get_backup_cli_path();

    // Given: cluster with 2 participants + 2 migration targets. Targets start
    // alongside the participants so their indexers sync before blocks pile up.
    let (mut cluster, running) =
        common::must_setup_cluster(common::MIGRATION_SERVICE_PORT_SEED, |c| {
            c.num_nodes = 2;
            c.threshold = 2;
            c.migration_targets = vec![0, 1];
        })
        .await;

    // Then: the cluster is healthy — sign + ckd requests succeed against the
    // source participants.
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");

    let target_indices = [2usize, 3];
    for (source_idx, &target_idx) in target_indices.iter().enumerate() {
        // Given: target shares the source's NEAR account but has a distinct
        // P2P key, and the cluster is still healthy from the prior iteration.
        assert_eq!(
            cluster.nodes[target_idx].account_id().to_string(),
            cluster.nodes[source_idx].account_id().to_string(),
            "migration target must share the source account"
        );
        assert_ne!(
            cluster.nodes[source_idx].p2p_public_key_str(),
            cluster.nodes[target_idx].p2p_public_key_str(),
            "migration target must have a different p2p key"
        );

        // When: run the migration flow end-to-end — register backup service,
        // GET keyshares from source, start migration, PUT keyshares to target,
        // wait for completion, then kill the source node.
        let backup_service = BackupService::must_get_new(backup_cli.clone());
        backup_service.must_generate_keys();
        register_backup_service_and_wait(&cluster, source_idx, &backup_service)
            .await
            .expect("register_backup_service_and_wait failed");
        get_keyshares_from_source(&cluster, source_idx, &backup_service)
            .await
            .expect("get_keyshares_from_source failed");
        start_migration_and_wait(&cluster, source_idx, target_idx)
            .await
            .expect("start_migration_and_wait failed");
        put_keyshares_to_target(&cluster, target_idx, &backup_service)
            .await
            .expect("put_keyshares_to_target failed");
        wait_for_migration_completion(&cluster, source_idx, target_idx)
            .await
            .expect("wait_for_migration_completion failed");
        cluster
            .kill_nodes(&[source_idx])
            .expect("failed to kill source node");

        // Then: with the source gone, the target has taken over — sign + ckd
        // requests still succeed.
        common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
            .await
            .expect("sign request failed");
        common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
            .await
            .expect("ckd request failed");

        tracing::info!(source_idx, target_idx, "migration completed successfully");
    }
}
