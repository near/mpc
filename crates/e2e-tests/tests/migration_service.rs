use crate::common;

use std::time::Duration;

use assert_cmd::Command;
use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcNodeState;
use near_mpc_contract_interface::types::ProtocolContractState;
use rand::SeedableRng;

struct BackupService {
    home_dir: tempfile::TempDir,
}

impl BackupService {
    fn new() -> Self {
        Self {
            home_dir: tempfile::tempdir().expect("failed to create backup service home dir"),
        }
    }

    fn cmd() -> Command {
        Command::cargo_bin("backup-cli").unwrap_or_else(|_| {
            tracing::info!("backup-cli binary not found — building");
            let status = std::process::Command::new("cargo")
                .args(["build", "-p", "backup-cli"])
                .status()
                .expect("failed to run cargo build for backup-cli");
            assert!(status.success(), "backup-cli build failed");
            Command::cargo_bin("backup-cli").expect("backup-cli not found after building")
        })
    }

    fn generate_keys(&self) {
        Self::cmd()
            .args([
                "--home-dir",
                self.home_dir.path().to_str().unwrap(),
                "generate-keys",
            ])
            .assert()
            .success();
    }

    fn public_key(&self) -> String {
        let secrets_path = self.home_dir.path().join("secrets.json");
        let secrets: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&secrets_path).unwrap()).unwrap();
        let p2p_key_bytes: Vec<u8> =
            serde_json::from_value(secrets["p2p_private_key"].clone()).unwrap();
        let secret_bytes: [u8; 32] = p2p_key_bytes
            .try_into()
            .expect("expected 32 bytes for signing key");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let pk = near_mpc_crypto_types::Ed25519PublicKey::from(&signing_key.verifying_key());
        String::from(&pk)
    }

    fn set_contract_state(&self, state: &ProtocolContractState) {
        let state_path = self.home_dir.path().join("contract_state.json");
        let json = serde_json::to_string_pretty(state).unwrap();
        std::fs::write(&state_path, json).unwrap();
    }

    fn get_keyshares(
        &self,
        node_migration_address: &str,
        node_p2p_key: &str,
        backup_encryption_key_hex: &str,
    ) {
        Self::cmd()
            .args([
                "--home-dir",
                self.home_dir.path().to_str().unwrap(),
                "get-keyshares",
                "--mpc-node-address",
                node_migration_address,
                "--mpc-node-p2p-key",
                node_p2p_key,
                "--backup-encryption-key-hex",
                backup_encryption_key_hex,
            ])
            .assert()
            .success();
    }

    fn put_keyshares(
        &self,
        node_migration_address: &str,
        node_p2p_key: &str,
        backup_encryption_key_hex: &str,
    ) {
        Self::cmd()
            .args([
                "--home-dir",
                self.home_dir.path().to_str().unwrap(),
                "put-keyshares",
                "--mpc-node-address",
                node_migration_address,
                "--mpc-node-p2p-key",
                node_p2p_key,
                "--backup-encryption-key-hex",
                backup_encryption_key_hex,
            ])
            .assert()
            .success();
    }
}

async fn wait_for_migration_port(address: &str) {
    let timeout = Duration::from_secs(120);
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
    .unwrap_or_else(|e| panic!("migration port {address} never became reachable: {e}"));
}

fn read_node_stderr(cluster: &e2e_tests::MpcCluster, idx: usize) -> String {
    let setup = match &cluster.nodes[idx] {
        MpcNodeState::Running(n) => n.setup(),
        MpcNodeState::Stopped(s) => s,
    };
    let stderr_path = setup.home_dir().join("stderr.log");
    match std::fs::read_to_string(&stderr_path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(50);
            lines[start..].join("\n")
        }
        Err(e) => format!("(could not read stderr.log: {e})"),
    }
}

fn running_state_matches_participant_key(
    state: &ProtocolContractState,
    account_id: &str,
    expected_pk: &str,
) -> bool {
    match state {
        ProtocolContractState::Running(r) => r
            .parameters
            .participants
            .participants
            .iter()
            .any(|(a, _, info)| a.0 == account_id && String::from(&info.sign_pk) == expected_pk),
        _ => false,
    }
}

/// Full end-to-end node migration via the backup CLI.
///
/// For each participating node in a 2-node cluster:
///   1. Register backup service
///   2. GET keyshares from source node
///   3. Initiate node migration
///   4. PUT keyshares to target node
///   5. Verify target node becomes active participant
///   6. Kill old node and verify sign requests succeed
#[tokio::test]
#[expect(non_snake_case)]
async fn migration_service__should_migrate_nodes_via_backup_cli() {
    // given
    let (mut cluster, running) = common::setup_cluster(common::MIGRATION_SERVICE_PORT_SEED, |c| {
        c.num_nodes = 2;
        c.threshold = 2;
    })
    .await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

    // when — migrate each node
    for source_idx in 0..2 {
        let backup_service = BackupService::new();
        backup_service.generate_keys();

        let source_account_id = cluster.nodes[source_idx].account_id().to_string();
        let source_p2p_key = cluster.nodes[source_idx].p2p_public_key_str();

        let target_idx = cluster
            .create_migration_target(source_idx)
            .expect("failed to create migration target");
        cluster
            .start_nodes(&[target_idx])
            .expect("failed to start target node");
        cluster
            .wait_for_node_healthy(target_idx)
            .await
            .expect("target node did not become healthy");

        let target_p2p_key = cluster.nodes[target_idx].p2p_public_key_str();
        let target_p2p_url = cluster.nodes[target_idx].p2p_url();

        assert_eq!(
            cluster.nodes[target_idx].account_id().to_string(),
            source_account_id,
            "migration target must share the source account"
        );
        assert_ne!(
            source_p2p_key, target_p2p_key,
            "migration target must have a different p2p key"
        );

        // Register backup service
        let backup_pk = backup_service.public_key();
        let outcome = cluster
            .register_backup_service(source_idx, serde_json::json!({ "public_key": backup_pk }))
            .await
            .expect("failed to register backup service");
        assert!(
            outcome.is_success(),
            "register_backup_service failed: {:?}",
            outcome.failure_message()
        );

        let wait_timeout = Duration::from_secs(30);
        (|| async {
            let info: serde_json::Value = cluster
                .view_migration_info()
                .await
                .expect("failed to view migration info");
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
                    (wait_timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
                ),
        )
        .await
        .expect("timed out waiting for node to index backup registration");

        let source_web_addr = match &cluster.nodes[source_idx] {
            MpcNodeState::Running(n) => n.web_address(),
            _ => panic!("source node not running"),
        };
        let http_client = reqwest::Client::new();
        (|| async {
            let resp = http_client
                .get(format!("http://{source_web_addr}/debug/migrations"))
                .send()
                .await?;
            let body = resp.text().await?;
            anyhow::ensure!(
                body.contains(&backup_pk),
                "node debug endpoint doesn't reflect backup registration yet"
            );
            Ok(())
        })
        .retry(
            ConstantBuilder::default()
                .with_delay(common::POLL_INTERVAL)
                .with_max_times(
                    (wait_timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
                ),
        )
        .await
        .expect("timed out waiting for node debug endpoint to show backup registration");

        // GET keyshares from source node
        let contract_state = cluster
            .get_contract_state()
            .await
            .expect("failed to get contract state");
        backup_service.set_contract_state(&contract_state);

        let source_migration_addr = match &cluster.nodes[source_idx] {
            MpcNodeState::Running(n) => n.migration_web_ui_address(),
            _ => panic!("source node not running"),
        };
        wait_for_migration_port(&source_migration_addr).await;
        backup_service.get_keyshares(
            &source_migration_addr,
            &source_p2p_key,
            cluster.nodes[source_idx].backup_encryption_key_hex(),
        );

        // Initiate node migration
        let target_signer_pk = cluster.nodes[target_idx].near_signer_public_key_str();
        let destination_node_info = serde_json::json!({
            "signer_account_pk": target_signer_pk,
            "destination_node_info": {
                "url": target_p2p_url,
                "sign_pk": target_p2p_key,
            },
        });
        let outcome = cluster
            .start_node_migration(source_idx, destination_node_info)
            .await
            .expect("failed to start node migration");
        assert!(
            outcome.is_success(),
            "start_node_migration failed: {:?}",
            outcome.failure_message()
        );

        (|| async {
            let info: serde_json::Value = cluster
                .view_migration_info()
                .await
                .expect("failed to view migration info");
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
                    (wait_timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
                ),
        )
        .await
        .expect("timed out waiting for contract to reflect node migration");

        // PUT keyshares to target node
        let contract_state = cluster
            .get_contract_state()
            .await
            .expect("failed to get contract state");
        backup_service.set_contract_state(&contract_state);

        let target_migration_addr = match &cluster.nodes[target_idx] {
            MpcNodeState::Running(n) => n.migration_web_ui_address(),
            _ => panic!("target node not running"),
        };
        let target_port_timeout = Duration::from_secs(120);
        let target_port_result: Result<(), _> = (|| async {
            let result = std::net::TcpStream::connect(&target_migration_addr);
            anyhow::ensure!(
                result.is_ok(),
                "migration port not yet listening at {target_migration_addr}"
            );
            Ok(())
        })
        .retry(
            ConstantBuilder::default()
                .with_delay(common::POLL_INTERVAL)
                .with_max_times(
                    (target_port_timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
                ),
        )
        .await;
        if target_port_result.is_err() {
            let stderr = read_node_stderr(&cluster, target_idx);
            panic!(
                "target node migration port {target_migration_addr} never became reachable.\n\
                 Node {target_idx} stderr (last 50 lines):\n{stderr}"
            );
        }
        backup_service.put_keyshares(
            &target_migration_addr,
            &target_p2p_key,
            cluster.nodes[target_idx].backup_encryption_key_hex(),
        );

        // then — verify target node becomes active participant
        let migration_timeout = Duration::from_secs(60);
        (|| async {
            let state = cluster
                .get_contract_state()
                .await
                .expect("failed to get contract state");
            anyhow::ensure!(
                running_state_matches_participant_key(&state, &source_account_id, &target_p2p_key,),
                "target node not yet active participant"
            );
            Ok(())
        })
        .retry(
            ConstantBuilder::default()
                .with_delay(common::POLL_INTERVAL)
                .with_max_times(
                    (migration_timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
                ),
        )
        .await
        .expect("timed out waiting for migration to complete");

        (|| async {
            let migration_info: serde_json::Value = cluster
                .view_migration_info()
                .await
                .expect("failed to view migration info");
            let entry = migration_info
                .get(&source_account_id)
                .expect("account not found in migration info");
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
        .expect("migration state did not clear");

        cluster
            .kill_nodes(&[source_idx])
            .expect("failed to kill source node");

        common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
            .await;
        common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
            .await;

        tracing::info!(source_idx, target_idx, "migration completed successfully");
    }
}
