use crate::{
    config::{
        generate_and_write_backup_encryption_key_to_disk, start::TeeAuthorityImpl as _, ConfigFile,
        PersistentSecrets, RespondConfig, SecretsConfig, StartConfig,
    },
    coordinator::Coordinator,
    db::SecretDB,
    indexer::{
        real::spawn_real_indexer, tx_sender::TransactionSender, IndexerAPI, ReadForeignChainPolicy,
    },
    keyshare::{GcpPermanentKeyStorageConfig, KeyStorageConfig, KeyshareStorage},
    migration_service::spawn_recovery_server_and_run_onboarding,
    profiler,
    tracing::init_logging,
    tracking::{self, start_root_task},
    web::{start_web_server, static_web_data, DebugRequest},
};
use anyhow::{anyhow, Context};
use mpc_attestation::report_data::ReportDataV1;
use mpc_contract::state::ProtocolContractState;
use mpc_primitives::hash::NodeImageHash;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_time::Clock;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tee_authority::tee_authority::TeeAuthority;
use tokio::sync::{broadcast, mpsc, oneshot, watch, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::tee::{
    remote_attestation::{monitor_attestation_removal, validate_remote_attestation},
    AllowedImageHashesFile,
};

pub const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

pub async fn run_mpc_node(config: StartConfig) -> anyhow::Result<()> {
    init_logging(&config.log);

    let root_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let _tokio_enter_guard = root_runtime.enter();

    // Load configuration and initialize persistent secrets
    let node_config = config.node.clone();
    let persistent_secrets = PersistentSecrets::generate_or_get_existing(
        &config.home_dir,
        node_config.number_of_responder_keys,
    )?;

    profiler::web_server::start_web_server(node_config.pprof_bind_address).await?;
    root_runtime.spawn(crate::metrics::tokio_task_metrics::run_monitor_loop());

    // TODO(#1296): Decide if the MPC responder account is actually needed
    let respond_config = RespondConfig::from_parts(&node_config, &persistent_secrets);

    let backup_encryption_key_hex = match &config.secrets.backup_encryption_key_hex {
        Some(key) => key.clone(),
        None => generate_and_write_backup_encryption_key_to_disk(&config.home_dir)?,
    };

    // Load secrets from configuration and persistent storage
    let secrets = SecretsConfig::from_parts(
        &config.secrets.secret_store_key_hex,
        persistent_secrets.clone(),
        &backup_encryption_key_hex,
    )?;

    // Generate attestation
    let tee_authority = config.tee.clone().into_tee_authority()?;
    let tls_public_key = &secrets.persistent_secrets.p2p_private_key.verifying_key();

    let account_public_key = &secrets.persistent_secrets.near_signer_key.verifying_key();

    let report_data = ReportDataV1::new(
        *Ed25519PublicKey::from(tls_public_key).as_bytes(),
        *Ed25519PublicKey::from(account_public_key).as_bytes(),
    )
    .into();

    let attestation = tee_authority.generate_attestation(report_data).await?;

    // Create communication channels and runtime
    let (debug_request_sender, _) = tokio::sync::broadcast::channel(10);
    let root_task_handle = Arc::new(OnceLock::new());

    let (protocol_state_sender, protocol_state_receiver) =
        watch::channel(ProtocolContractState::NotInitialized);

    let (migration_state_sender, migration_state_receiver) = watch::channel((0, BTreeMap::new()));
    let web_server = root_runtime
        .block_on(start_web_server(
            root_task_handle.clone(),
            debug_request_sender.clone(),
            node_config.web_ui,
            static_web_data(&secrets, Some(attestation)),
            protocol_state_receiver,
            migration_state_receiver,
            config.node.clone(),
        ))
        .context("Failed to create web server.")?;

    let _web_server_join_handle = root_runtime.spawn(web_server);

    // Create Indexer and wait for indexer to be synced.
    let (indexer_exit_sender, indexer_exit_receiver) = oneshot::channel();
    let (indexer_api, chain_gateway) = spawn_real_indexer(
        config.home_dir.clone(),
        node_config.indexer.clone(),
        node_config.my_near_account_id.clone(),
        persistent_secrets.near_signer_key.clone(),
        respond_config,
        indexer_exit_sender,
        protocol_state_sender,
        migration_state_sender,
        *tls_public_key,
    );

    // Initialize TeeContext using chain-gateway for hash watching and transaction submission
    let cg_signer = chain_gateway::transaction_sender::TransactionSigner::from_key(
        node_config.my_near_account_id.clone(),
        persistent_secrets.near_signer_key.clone(),
    );
    let cg_tx_sender =
        chain_gateway::transaction_sender::TransactionSender::new(chain_gateway.clone(), cg_signer);
    let tee_ctx = root_runtime
        .block_on(tee_context::TeeContext::new(
            chain_gateway,
            node_config.indexer.mpc_contract_id.clone(),
            cg_tx_sender,
        ))
        .context("Failed to initialize TeeContext")?;

    let (shutdown_signal_sender, mut shutdown_signal_receiver) = mpsc::channel(1);
    let cancellation_token = CancellationToken::new();

    // Spawn hash watcher: writes allowed hashes to disk for the launcher
    let image_hash_storage =
        AllowedImageHashesFile::from(config.tee.latest_allowed_hash_file_path.clone());
    let current_image = NodeImageHash::from(config.tee.image_hash.as_bytes());
    let mut hashes_rx = tee_ctx.watch_allowed_tee_hashes();
    let shutdown_sender_clone = shutdown_signal_sender.clone();
    let child_token = cancellation_token.child_token();
    let image_hash_watcher_handle = root_runtime.spawn(async move {
        loop {
            tokio::select! {
                _ = child_token.cancelled() => {
                    return Ok(());
                }
                result = hashes_rx.changed() => {
                    if let Err(e) = result {
                        tracing::error!("TeeContext hash watcher closed: {e}");
                        let _ = shutdown_sender_clone.send(()).await;
                        return Err(anyhow!("TeeContext hash watcher closed"));
                    }
                    let hashes = hashes_rx.borrow().clone();
                    let image_hashes = &hashes.allowed_docker_image_hashes;

                    if !image_hashes.contains(&current_image) {
                        tracing::warn!(
                            "Current image hash is not in the allowed list. \
                             The node may be evicted."
                        );
                    }

                    let non_empty = match near_mpc_bounded_collections::NonEmptyVec::try_from_vec(
                        image_hashes.iter().copied().collect(),
                    ) {
                        Some(v) => v,
                        None => {
                            tracing::warn!("Allowed image hashes list is empty, skipping disk write");
                            continue;
                        }
                    };

                    if let Err(e) = image_hash_storage.set(non_empty).await {
                        tracing::error!("Failed to write allowed hashes to disk: {e}");
                        let _ = shutdown_sender_clone.send(()).await;
                        return Err(anyhow!("Failed to write allowed hashes to disk: {e}"));
                    }
                }
            }
        }
    });

    let home_dir = config.home_dir.clone();
    let root_future = create_root_future(
        config,
        home_dir.clone(),
        node_config.clone(),
        secrets.clone(),
        indexer_api,
        debug_request_sender,
        root_task_handle,
        tee_authority,
        tee_ctx,
    );

    let root_task = root_runtime.spawn(start_root_task("root", root_future).0);

    let exit_reason = tokio::select! {
        root_task_result = root_task => {
            root_task_result?
        }
        indexer_exit_response = indexer_exit_receiver => {
            indexer_exit_response.context("Indexer thread dropped response channel.")?
        }
        Some(()) = shutdown_signal_receiver.recv() => {
            Err(anyhow!("TEE allowed image hashes watcher is sending shutdown signal."))
        }
    };

    // Perform graceful shutdown
    cancellation_token.cancel();

    info!("Waiting for image hash watcher to gracefully exit.");
    let exit_result = image_hash_watcher_handle.await;
    info!(?exit_result, "Image hash watcher exited.");

    exit_reason
}

#[expect(clippy::too_many_arguments)]
async fn create_root_future<TransactionSenderImpl, ForeignChainPolicyReader>(
    start_config: StartConfig,
    home_dir: PathBuf,
    config: ConfigFile,
    secrets: SecretsConfig,
    indexer_api: IndexerAPI<TransactionSenderImpl, ForeignChainPolicyReader>,
    debug_request_sender: broadcast::Sender<DebugRequest>,
    // Cloning a OnceLock returns a new cell, which is why we have to wrap it in an arc.
    // Otherwise we would not write to the same cell/lock.
    root_task_handle_once_lock: Arc<OnceLock<Arc<tracking::TaskHandle>>>,
    tee_authority: TeeAuthority,
    tee_ctx: tee_context::TeeContext,
) -> anyhow::Result<()>
where
    TransactionSenderImpl: TransactionSender + 'static,
    ForeignChainPolicyReader: ReadForeignChainPolicy + Clone + Send + Sync + 'static,
{
    let root_task_handle = tracking::current_task();

    root_task_handle_once_lock
        .set(root_task_handle.clone())
        .map_err(|_| anyhow!("Root task handle was already set"))?;

    let tls_public_key =
        Ed25519PublicKey::from(&secrets.persistent_secrets.p2p_private_key.verifying_key());
    let account_public_key =
        Ed25519PublicKey::from(&secrets.persistent_secrets.near_signer_key.verifying_key());

    let secret_db = SecretDB::new(&home_dir.join("assets"), secrets.local_storage_aes_key)?;

    let key_storage_config = KeyStorageConfig {
        home_dir: home_dir.clone(),
        local_encryption_key: secrets.local_storage_aes_key,
        gcp: start_config.gcp.map(|gcp| GcpPermanentKeyStorageConfig {
            project_id: gcp.project_id,
            secret_id: gcp.keyshare_secret_id,
        }),
    };

    // Spawn periodic attestation submission task using TeeContext
    {
        let tee_authority = tee_authority.clone();
        let tee_ctx = tee_ctx.clone();
        let tls_public_key = tls_public_key.clone();
        let account_public_key = account_public_key.clone();
        let hashes_rx = tee_ctx.watch_allowed_tee_hashes();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(ATTESTATION_RESUBMISSION_INTERVAL);
            loop {
                interval.tick().await;
                let attestation = match tee_authority
                    .generate_attestation(
                        mpc_attestation::report_data::ReportDataV1::new(
                            *tls_public_key.as_bytes(),
                            *account_public_key.as_bytes(),
                        )
                        .into(),
                    )
                    .await
                {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(error = ?e, "failed to generate attestation");
                        continue;
                    }
                };

                // Validate locally before submitting
                let hashes = hashes_rx.borrow().clone();
                if let Err(e) = validate_remote_attestation(
                    &attestation,
                    tls_public_key.clone(),
                    account_public_key.clone(),
                    &hashes.allowed_docker_image_hashes,
                    &hashes.allowed_launcher_compose_hashes,
                ) {
                    tracing::warn!(error = ?e, "local attestation validation failed, submitting anyway");
                }

                if let Err(e) = tee_ctx
                    .submit_attestation(
                        attestation.into_contract_interface_type(),
                        tls_public_key.clone(),
                    )
                    .await
                {
                    tracing::error!(error = ?e, "periodic attestation submission failed");
                }
            }
        });
    }

    // Spawn TEE attestation monitoring task
    {
        let tee_accounts_receiver = indexer_api.attested_nodes_receiver.clone();
        let account_id = config.my_near_account_id.clone();
        let tee_ctx = tee_ctx.clone();
        let tls_public_key = tls_public_key.clone();
        let account_public_key = account_public_key.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor_attestation_removal(
                account_id,
                tee_authority,
                tee_ctx,
                tls_public_key,
                account_public_key,
                tee_accounts_receiver,
            )
            .await
            {
                tracing::error!(
                    error = ?e,
                    "attestation removal monitoring task failed"
                );
            }
        });
    }

    let keyshare_storage: Arc<RwLock<KeyshareStorage>> =
        RwLock::new(key_storage_config.create().await?).into();

    spawn_recovery_server_and_run_onboarding(
        config.migration_web_ui,
        (&secrets).into(),
        config.my_near_account_id.clone(),
        keyshare_storage.clone(),
        indexer_api.my_migration_info_receiver.clone(),
        indexer_api.contract_state_receiver.clone(),
        indexer_api.txn_sender.clone(),
    )
    .await?;

    let coordinator = Coordinator {
        clock: Clock::real(),
        config_file: config,
        secrets,
        secret_db,
        keyshare_storage,
        indexer: indexer_api,
        currently_running_job_name: Arc::new(Mutex::new(String::new())),
        debug_request_sender,
    };
    coordinator.run().await
}
