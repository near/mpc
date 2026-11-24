use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use backon::{ConstantBuilder, Retryable};
use e2e_tests::mpc_node::{ProcessGuard, local_tee_config, sandbox_near_init};
use mpc_node_config::{BackupServiceStartConfig, SecretsStartConfig, default_pccs_endpoints};
use near_contract_transport::WatchContractState;
use near_mpc_contract_interface::types::BackupServiceInfo;
use node_types::http_server::StaticWebData;
use test_port_allocator::reserve_port;

use crate::common;

const BACKUP_SERVICE_TIMEOUT: Duration = Duration::from_mins(2);

#[tokio::test]
#[expect(non_snake_case)]
async fn backup_service_tee__should_restore_keyshares_into_the_migration_target() {
    // Given
    let num_nodes = 2;
    let (source_idx, target_idx) = (0, num_nodes);
    let (cluster, running) =
        common::must_setup_cluster(common::BACKUP_SERVICE_TEE_PORT_SEED, |c| {
            c.contract_wasm = common::must_load_mock_attestation_contract_wasm();
            c.num_nodes = num_nodes;
            c.threshold = num_nodes;
            c.migration_targets = vec![source_idx];
        })
        .await;
    let account_id = cluster.nodes[source_idx].account_id().clone();
    let home_dir = cluster.test_dir.path().join("backup_service");
    std::fs::create_dir_all(&home_dir).expect("failed to create the backup service home dir");
    let config = BackupServiceStartConfig {
        tee: local_tee_config(home_dir.join("latest_allowed_hash.txt")),
        account_id: account_id.clone(),
        mpc_contract_id: cluster.contract_id().clone(),
        genesis_hash: cluster.blockchain.genesis_hash().await.unwrap(),
        near_init: sandbox_near_init(
            cluster.sandbox.chain_id().unwrap(),
            cluster.sandbox.boot_nodes().unwrap(),
            cluster.sandbox.genesis_path(),
            reserve_port(),
            reserve_port(),
        ),
        secrets: SecretsStartConfig {
            secret_store_key_hex: hex::encode([0; 16]),
            backup_encryption_key_hex: Some(
                cluster.nodes[source_idx]
                    .backup_encryption_key_hex()
                    .to_owned(),
            ),
        },
        mpc_node_migration_port: cluster.ports.migration_web_ui_port(source_idx),
        listen_address: SocketAddr::from(([127, 0, 0, 1], reserve_port())),
        pccs_endpoints: default_pccs_endpoints(),
    };

    let backup_service = start_backup_service(&home_dir, &config);
    let public_data = wait_for_public_data(config.listen_address)
        .await
        .expect("the backup service did not serve its keys");
    cluster
        .blockchain
        .add_function_call_key(
            &account_id,
            &cluster.operator_keys[source_idx],
            near_kit::signer::PublicKey::ed25519_from_bytes(
                *public_data.near_signer_public_key.as_bytes(),
            )
            .unwrap(),
            cluster.contract_id(),
        )
        .await
        .expect("failed to add the backup service's account key");
    cluster
        .prepay_attestation_grant(source_idx)
        .await
        .expect("failed to prepay the backup service's grant");
    let attested_backup_service = Some(BackupServiceInfo {
        public_key: public_data.near_p2p_public_key,
    });
    cluster
        .mpc_contract_handle
        .attested_backup_service(account_id)
        .subscribe()
        .await
        .wait_for(BACKUP_SERVICE_TIMEOUT, |backup_service| {
            *backup_service == attested_backup_service
        })
        .await
        .expect("the backup service did not register its attestation");
    common::wait_for_backed_up_epoch(
        &home_dir,
        running.keyset.epoch_id.get(),
        running.keyset.domains.len(),
    )
    .await
    .expect("the backup service did not back up the keyset");

    // Local nodes listen on distinct migration ports and use distinct backup encryption keys
    drop(backup_service);
    let config = BackupServiceStartConfig {
        mpc_node_migration_port: cluster.ports.migration_web_ui_port(target_idx),
        secrets: SecretsStartConfig {
            backup_encryption_key_hex: Some(
                cluster.nodes[target_idx]
                    .backup_encryption_key_hex()
                    .to_owned(),
            ),
            ..config.secrets
        },
        ..config
    };
    let _backup_service = start_backup_service(&home_dir, &config);
    wait_for_public_data(config.listen_address)
        .await
        .expect("the restarted backup service did not serve its keys");

    // When
    common::start_migration_and_wait(&cluster, source_idx, target_idx)
        .await
        .expect("start_migration_and_wait failed");

    // Then
    common::wait_for_migration_completion(&cluster, source_idx, target_idx)
        .await
        .expect("the target did not conclude the migration");
}

/// Writes the config into the home dir and starts the backup service from it, as a launcher does
fn start_backup_service(home_dir: &Path, config: &BackupServiceStartConfig) -> ProcessGuard {
    let config_path = home_dir.join("backup_service_config.toml");
    std::fs::write(
        &config_path,
        toml::to_string(config).expect("failed to serialize the backup service config"),
    )
    .expect("failed to write the backup service config");
    let child = Command::new(common::must_get_backup_cli_path())
        .arg("--home-dir")
        .arg(home_dir)
        .arg("start-with-config-file")
        .arg(&config_path)
        .spawn()
        .expect("failed to spawn backup-cli start-with-config-file");
    ProcessGuard(child)
}

async fn wait_for_public_data(listen_address: SocketAddr) -> anyhow::Result<StaticWebData> {
    let url = format!("http://{listen_address}/public_data");
    let fetch =
        || async { anyhow::Ok(reqwest::get(&url).await?.error_for_status()?.json().await?) };
    tokio::time::timeout(
        BACKUP_SERVICE_TIMEOUT,
        fetch.retry(
            ConstantBuilder::default()
                .with_delay(common::POLL_INTERVAL)
                .without_max_times(),
        ),
    )
    .await
    .context("timed out waiting for /public_data")?
}
