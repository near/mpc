use crate::{
    config::{
        PersistentSecrets, RespondConfig, SecretsConfig,
        generate_and_write_backup_encryption_key_to_disk,
        start::{TeeAuthorityImpl as _, read_near_config_json},
    },
    coordinator::Coordinator,
    db::SecretDB,
    home_paths::assets_dir,
    indexer::{IndexerAPI, real::spawn_real_indexer, tx_sender::TransactionSender},
    keyshare::{GcpPermanentKeyStorageConfig, KeyStorageConfig, KeyshareStorage},
    migration_service::spawn_recovery_server_and_run_onboarding,
    profiler,
    tracing::init_logging,
    tracking::{self, start_root_task},
    types::SubmittedTransaction,
    web::{
        DebugRequest,
        recent_transactions::{
            RECENT_TRANSACTIONS_CHANNEL_SIZE, RecentTransactionsLogger, SharedRecentTransactions,
            spawn_recent_transactions_drain,
        },
        start_web_server, static_web_data,
    },
};
use anyhow::{Context, anyhow};
use itertools::Itertools;
use mpc_attestation::report_data::ReportDataV1;
use mpc_node_config::{ConfigFile, StartConfig};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_mpc_contract_interface::types::ProtocolContractState;
use near_time::Clock;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tee_authority::tee_authority::TeeAuthority;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::tee::{
    AllowedImageHashesFile, monitor_allowed_image_hashes,
    remote_attestation::{monitor_attestation_removal, periodic_attestation_submission},
};

pub const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

pub async fn run_mpc_node(config: StartConfig) -> anyhow::Result<()> {
    init_logging(&config.log);

    // Log startup info
    tracing::info!("{}", *crate::MPC_VERSION_STRING);
    tracing::info!(
        account_id = %config.node.my_near_account_id,
        contract_id = %config.node.indexer.mpc_contract_id,
        home_dir = %config.home_dir.display(),
        web_ui = %config.node.web_ui,
        "starting MPC node"
    );
    tracing::info!(
        tee_authority = %match &config.tee.authority {
            launcher_interface::types::TeeAuthorityConfig::Dstack { .. } => "dstack",
            launcher_interface::types::TeeAuthorityConfig::Local => "local",
        },
        image_hash = %config.tee.image_hash,
        pccs_endpoints = %config.pccs_endpoints.iter().map(|e| e.url.as_str()).join(", "),
        "TEE config"
    );
    if let Some(ref near_init) = config.near_init {
        tracing::info!(
            chain_id = %near_init.chain_id,
            download_genesis = near_init.download_genesis,
            "NEAR init config"
        );
    }

    let root_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let _tokio_enter_guard = root_runtime.enter();

    // Install the SIGTERM handler as the first thing after the runtime is
    // built, BEFORE any expensive startup (indexer bootstrap, contract
    // state fetch, attestation generation). A SIGTERM arriving during
    // that window would otherwise hit the process with no handler
    // installed and the OS would terminate us immediately — functionally
    // identical to SIGKILL.
    //
    // If install fails (which would only happen if the host's signal
    // subsystem is fundamentally broken — in which case nothing else
    // about the node is going to work either), we log and degrade to
    // the pre-handler baseline: SIGTERM OS-default-terminates. The rest
    // of the node still runs.
    let mut sigterm_handle = signal(SignalKind::terminate())
        .inspect_err(|e| tracing::error!(error = %e, "failed to install SIGTERM handler — graceful shutdown disabled"))
        .ok();

    // Load configuration and initialize persistent secrets
    let node_config = config.node.clone();
    let persistent_secrets = PersistentSecrets::generate_or_get_existing(
        &config.home_dir,
        node_config.number_of_responder_keys,
    )?;

    profiler::web_server::start_web_server(node_config.pprof_bind_address).await?;
    root_runtime.spawn(crate::metrics::tokio_task_metrics::run_monitor_loop());

    // TODO(#2102): Decide if the MPC responder account is actually needed
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
    let tee_authority = config
        .tee
        .clone()
        .into_tee_authority(config.pccs_endpoints.clone())?;
    let tls_public_key = &secrets.persistent_secrets.p2p_private_key.verifying_key();

    let account_public_key = &secrets.persistent_secrets.near_signer_key.verifying_key();

    let report_data = ReportDataV1::new(
        *Ed25519PublicKey::from(tls_public_key).as_bytes(),
        *Ed25519PublicKey::from(account_public_key).as_bytes(),
    )
    .into();

    let attestation = match tee_authority.generate_attestation(report_data).await {
        Ok(att) => {
            crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_SUCCESS])
                .inc();
            tracing::info!("TEE attestation generated successfully");
            Some(att)
        }
        Err(tee_authority::tee_authority::AttestationError::CollateralFetch(e)) => {
            crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                .inc();
            tracing::error!(
                error = %e,
                "TEE attestation failed. Node will continue without attestation and retry periodically",
            );
            None
        }
        Err(e) => {
            crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                .inc();
            return Err(anyhow::anyhow!(e).context("TEE attestation failed, cannot continue"));
        }
    };

    // Create communication channels and runtime
    let (debug_request_sender, _) = tokio::sync::broadcast::channel(10);
    let root_task_handle = Arc::new(OnceLock::new());

    let (protocol_state_sender, protocol_state_receiver) =
        watch::channel(ProtocolContractState::NotInitialized);

    let (migration_state_sender, migration_state_receiver) = watch::channel((0, BTreeMap::new()));

    // Buffer behind the recent-transactions debug page. The indexer forwards
    // records over `recent_tx_sender`; the drain task records them into the
    // buffer, which the web server reads for snapshots.
    let (recent_tx_sender, recent_tx_receiver) =
        mpsc::channel::<SubmittedTransaction>(RECENT_TRANSACTIONS_CHANNEL_SIZE);
    let recent_transactions = SharedRecentTransactions::default();
    spawn_recent_transactions_drain(recent_tx_receiver, recent_transactions.clone());

    let web_server = root_runtime
        .block_on(start_web_server(
            root_task_handle.clone(),
            debug_request_sender.clone(),
            node_config.web_ui,
            static_web_data(&secrets, attestation),
            protocol_state_receiver,
            migration_state_receiver,
            config.node.clone(),
            read_near_config_json(&config.home_dir),
            recent_transactions.clone(),
        ))
        .context("Failed to create web server.")?;

    let _web_server_join_handle = root_runtime.spawn(web_server);

    // Create Indexer and wait for indexer to be synced.
    let (indexer_exit_sender, indexer_exit_receiver) = oneshot::channel();
    // Dedicated cancellation token for the indexer thread. Cancelled after
    // `shutdown_all_actors()` below so the indexer's terminal `listen_blocks`
    // race exits, its tokio runtime drops, and the Arc<RocksDB> references
    // held by its spawned monitor tasks are released — enabling
    // `RocksDB::block_until_all_instances_are_dropped()` to return.
    let indexer_shutdown_token = CancellationToken::new();
    let indexer_api = spawn_real_indexer(
        config.home_dir.clone(),
        node_config.indexer.clone(),
        node_config.my_near_account_id.clone(),
        persistent_secrets.near_signer_key.clone(),
        respond_config,
        indexer_exit_sender,
        protocol_state_sender,
        migration_state_sender,
        *tls_public_key,
        node_config.foreign_chains.clone(),
        RecentTransactionsLogger::new(recent_tx_sender),
        indexer_shutdown_token.clone(),
    );

    let cancellation_token = CancellationToken::new();

    let allowed_hashes_in_contract = indexer_api.allowed_docker_images_receiver.clone();
    let image_hash_storage =
        AllowedImageHashesFile::from(config.tee.latest_allowed_hash_file_path.clone());

    // Dedicated shutdown channel for the image-hash watcher. The watcher's
    // Drop fires this on its rare exceptional exits (storage I/O failure
    // or indexer's contract-state channel closed); the main `select!`
    // arm below converts that into a non-zero process exit.
    let (image_hash_shutdown_sender, mut image_hash_shutdown_receiver) = mpsc::channel(1);

    let image_hash_watcher_handle = root_runtime.spawn(monitor_allowed_image_hashes(
        cancellation_token.child_token(),
        *config.tee.image_hash,
        allowed_hashes_in_contract,
        image_hash_storage,
        image_hash_shutdown_sender,
    ));

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
    );

    let root_task = root_runtime.spawn(start_root_task("root", root_future).0);

    let exit_reason: anyhow::Result<()> = tokio::select! {
        root_task_result = root_task => {
            root_task_result?
        }
        indexer_exit_response = indexer_exit_receiver => {
            indexer_exit_response.context("Indexer thread dropped response channel.")?
        }
        // Race SIGTERM directly. If install above failed, `sigterm_handle`
        // is `None` and this arm is parked on `pending()` forever — i.e.
        // effectively absent — so the other arms still drive the loop.
        _ = async {
            match sigterm_handle.as_mut() {
                Some(s) => { s.recv().await; }
                None => std::future::pending().await,
            }
        } => {
            info!(signal = "SIGTERM", "shutdown signal received; exiting cleanly");
            Ok(())
        }
        Some(()) = image_hash_shutdown_receiver.recv() => {
            // The specific `ExitError` (storage I/O failure or indexer's
            // contract-state channel closed) is logged a few lines below via
            // `info!(?exit_result, "Image hash watcher exited.")`.
            Err(anyhow!("TEE allowed-image-hashes watcher exited unexpectedly."))
        }
    };

    // Perform graceful shutdown
    cancellation_token.cancel();

    info!("Waiting for image hash watcher to gracefully exit.");
    let exit_result = image_hash_watcher_handle.await;
    info!(?exit_result, "Image hash watcher exited.");

    // Stop nearcore's actor system so its tasks have a chance to commit any
    // in-flight RocksDB batches before the process exits.
    info!("Stopping nearcore actor system.");
    near_async::shutdown_all_actors();

    // Cancel the indexer's terminal `listen_blocks` race; that lets the
    // indexer thread's `block_on` return, its tokio runtime drop, and every
    // spawned monitor task (each holding `Arc<IndexerState>` →
    // `Arc<RocksDB>`) be aborted with the runtime.
    info!("Cancelling indexer shutdown token.");
    indexer_shutdown_token.cancel();

    // Now block until every RocksDB instance has actually been dropped —
    // mirroring what neard's standalone binary does on its SIGTERM path.
    // Without the cancellation above this call would hang forever because
    // the indexer thread's monitor tasks keep their Arc<RocksDB> alive.
    info!("Waiting for RocksDB instances to gracefully shut down.");
    near_store::db::RocksDB::block_until_all_instances_are_dropped();
    info!("RocksDB shutdown complete.");

    exit_reason
}

#[expect(clippy::too_many_arguments)]
async fn create_root_future<TransactionSenderImpl>(
    start_config: StartConfig,
    home_dir: PathBuf,
    config: ConfigFile,
    secrets: SecretsConfig,
    indexer_api: IndexerAPI<TransactionSenderImpl>,
    debug_request_sender: broadcast::Sender<DebugRequest>,
    // Cloning a OnceLock returns a new cell, which is why we have to wrap it in an arc.
    // Otherwise we would not write to the same cell/lock.
    root_task_handle_once_lock: Arc<OnceLock<Arc<tracking::TaskHandle>>>,
    tee_authority: TeeAuthority,
) -> anyhow::Result<()>
where
    TransactionSenderImpl: TransactionSender + 'static,
{
    let root_task_handle = tracking::current_task();

    root_task_handle_once_lock
        .set(root_task_handle.clone())
        .map_err(|_| anyhow!("Root task handle was already set"))?;

    let tls_public_key =
        Ed25519PublicKey::from(&secrets.persistent_secrets.p2p_private_key.verifying_key());
    let account_public_key =
        Ed25519PublicKey::from(&secrets.persistent_secrets.near_signer_key.verifying_key());

    let secret_db = SecretDB::new(&assets_dir(&home_dir), secrets.local_storage_aes_key)?;

    let key_storage_config = KeyStorageConfig {
        home_dir: home_dir.clone(),
        local_encryption_key: secrets.local_storage_aes_key,
        gcp: start_config.gcp.map(|gcp| GcpPermanentKeyStorageConfig {
            project_id: gcp.project_id,
            secret_id: gcp.keyshare_secret_id,
        }),
    };

    // Spawn periodic attestation submission task
    let tee_authority_clone = tee_authority.clone();
    let tx_sender_clone = indexer_api.txn_sender.clone();
    let tls_public_key_clone = tls_public_key.clone();
    let account_public_key_clone = account_public_key.clone();
    let allowed_docker_images_receiver_clone = indexer_api.allowed_docker_images_receiver.clone();
    let allowed_launcher_compose_receiver_clone =
        indexer_api.allowed_launcher_compose_receiver.clone();
    tokio::spawn(async move {
        if let Err(e) = periodic_attestation_submission(
            tee_authority_clone,
            tx_sender_clone,
            tls_public_key_clone,
            account_public_key_clone,
            allowed_docker_images_receiver_clone,
            allowed_launcher_compose_receiver_clone,
            tokio::time::interval(ATTESTATION_RESUBMISSION_INTERVAL),
        )
        .await
        {
            tracing::error!(
                error = ?e,
                "periodic attestation submission task failed"
            );
        }
    });

    // Spawn TEE attestation monitoring task
    let tx_sender_clone = indexer_api.txn_sender.clone();
    let tee_accounts_receiver = indexer_api.attested_nodes_receiver.clone();
    let account_id_clone = config.my_near_account_id.clone();
    let allowed_docker_images_receiver_clone = indexer_api.allowed_docker_images_receiver.clone();
    let allowed_launcher_compose_receiver_clone =
        indexer_api.allowed_launcher_compose_receiver.clone();
    tokio::spawn(async move {
        if let Err(e) = monitor_attestation_removal(
            account_id_clone,
            tee_authority,
            tx_sender_clone,
            tls_public_key,
            account_public_key,
            allowed_docker_images_receiver_clone,
            allowed_launcher_compose_receiver_clone,
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
