use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use chain_gateway::{
    ChainGateway, NodeConfig,
    transaction_sender::{AccountCaller, TransactionSigner},
};
use mpc_node::{
    config::{PersistentSecrets, SecretsConfig, ensure_near_initialized},
    web::static_web_data,
};
use mpc_node_config::BackupServiceStartConfig;
use near_mpc_contract_interface::{
    client::MpcContractHandle,
    types::{Attestation, BackupServiceInfo, Ed25519PublicKey},
};
use tee_authority::tee_authority::TeeAuthority;
use tee_context::{
    AllowedImageHashesFile, AttestationSubmitter, SubmitAttestation, TeeService, TeeStateMonitors,
    generate_initial_attestation, init_attestation_freshness_metrics, monitor_allowed_image_hashes,
    run_periodic_attestation_submission,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    adapters::{
        chain_listed_nodes::ChainListedNodes, keyshare_storage::KeyshareStorageAdapter, web,
    },
    backup::run_backup_service_through_embedded_node,
    cli::{DEFAULT_POLL_INTERVAL_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS},
};

/// Starts the backup service a launcher configured, serves its keys and attestation on
/// `/public_data`, registers it on the contract every hour, and backs up the keyshares of its
/// account's MPC node until the given [`CancellationToken`] is cancelled. Fails when the embedded
/// NEAR node follows a chain other than the configured genesis hash's, or when the approved image
/// hashes cannot be written for the launcher.
pub async fn start_with_config_file(
    home_dir: PathBuf,
    config: BackupServiceStartConfig,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    ensure_near_initialized(&home_dir, &config.near_init, &config.mpc_contract_id)?;
    let (chain_gateway, _near_node, _) =
        ChainGateway::start(NodeConfig::new(home_dir.clone()), None, shutdown.clone()).await?;
    chain_gateway
        .ensure_chain_matches(Some(config.genesis_hash))
        .await?;

    let secrets = SecretsConfig::from_parts(
        &config.secrets.secret_store_key_hex,
        PersistentSecrets::generate_or_get_existing(&home_dir)?,
        config
            .secrets
            .backup_encryption_key_hex
            .as_deref()
            .context("the backup service needs its MPC node's backup encryption key")?,
    )?;
    let keys = static_web_data(&secrets.persistent_secrets, None);
    let tee_authority = TeeAuthority::new(config.tee.authority, config.pccs_endpoints)?;
    let attestation = generate_initial_attestation(
        &tee_authority,
        &keys.near_p2p_public_key,
        &keys.near_signer_public_key,
    )
    .await?;
    let (latest_attestation_sender, latest_attestation) = watch::channel(attestation);

    let mpc_contract =
        MpcContractHandle::new(chain_gateway.clone(), config.mpc_contract_id.clone());
    let (tee_state_monitors, tee) = TeeStateMonitors::new();
    tee_state_monitors.spawn(
        mpc_contract.clone(),
        TeeService::BackupService,
        keys.near_p2p_public_key.clone(),
    );

    let (image_hash_shutdown_sender, mut image_hash_shutdown) = mpsc::channel(1);
    let image_hash_watcher = tokio::spawn(monitor_allowed_image_hashes(
        shutdown.child_token(),
        *config.tee.image_hash,
        tee.allowed_image_hashes.clone(),
        AllowedImageHashesFile::from(config.tee.latest_allowed_hash_file_path),
        image_hash_shutdown_sender,
    ));

    let signer = TransactionSigner::from_key(
        config.account_id.clone(),
        secrets.persistent_secrets.near_signer_key,
    );
    tokio::spawn(run_periodic_attestation_submission(AttestationSubmitter {
        tee_authority,
        submitter: RegisterBackupService(Arc::new(MpcContractHandle::new(
            AccountCaller::new(chain_gateway, [signer].into()),
            config.mpc_contract_id,
        ))),
        tls_public_key: keys.near_p2p_public_key.clone(),
        account_public_key: keys.near_signer_public_key.clone(),
        tee,
        latest_attestation: latest_attestation_sender,
    }));

    init_attestation_freshness_metrics();
    let (status_reporter, status) = web::status_channel();
    web::spawn_web_server(
        config.listen_address,
        status,
        Some(web::PublicData {
            keys,
            latest_attestation,
        }),
    )
    .await?;

    let mpc_nodes = ChainListedNodes::new(
        mpc_contract.clone(),
        config.account_id,
        config.mpc_node_migration_port,
        secrets.persistent_secrets.p2p_private_key,
        secrets.backup_encryption_key,
        Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS),
    );
    let keyshares_storage =
        KeyshareStorageAdapter::new(home_dir, secrets.local_storage_aes_key).await?;
    tokio::select! {
        result = run_backup_service_through_embedded_node(
            &mpc_contract,
            mpc_nodes,
            keyshares_storage,
            status_reporter,
            Duration::from_secs(DEFAULT_POLL_INTERVAL_SECONDS),
            shutdown,
        ) => result,
        Some(()) = image_hash_shutdown.recv() => {
            Err(anyhow!(
                "the approved image hashes watcher exited unexpectedly: {:?}",
                image_hash_watcher.await
            ))
        }
    }
}

/// Registers the backup service with the account key generated inside the TEE. Nothing else
/// signs with that key, so this caller's nonce counter is the only one in use.
#[derive(Clone)]
struct RegisterBackupService(Arc<MpcContractHandle<AccountCaller<ChainGateway>>>);

impl SubmitAttestation for RegisterBackupService {
    async fn submit(
        &self,
        attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> anyhow::Result<()> {
        self.0
            .register_backup_service(
                BackupServiceInfo {
                    public_key: tls_public_key,
                },
                attestation,
            )
            .await?;
        Ok(())
    }
}
