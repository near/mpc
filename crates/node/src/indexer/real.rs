use super::foreign_chain::monitor_foreign_chain_supporters;
use super::handler::listen_blocks;
use super::migrations::{ContractMigrationInfo, monitor_migrations};
use super::near_data_wipe::{
    record_epoch_sync_reset_request, wipe_near_data_if_epoch_sync_reset,
    wipe_near_data_if_requested,
};
use super::participants::monitor_contract_state;
use super::stats::indexer_logger;
use super::{IndexerAPI, IndexerState, RealAttestationExpiryReader};
use crate::config::RespondConfig;
#[cfg(feature = "network-hardship-simulation")]
use crate::config::load_listening_blocks_file;
use crate::home_paths::{epoch_sync_reset_marker_file, near_data_dir};
use crate::indexer::configs::IndexerConfigExt;
use crate::indexer::tee::{
    monitor_allowed_docker_images, monitor_allowed_foreign_chain_providers,
    monitor_allowed_launcher_compose_hashes,
};
use crate::indexer::tx_sender::{TransactionProcessorHandle, TransactionSender};
use crate::types::LogTransaction;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_node_config::IndexerConfig;
use near_account_id::AccountId;
use near_async::ActorSystem;
use near_client::client_actor::ShutdownReason;
use near_indexer::Indexer;
use near_mpc_contract_interface::types::ProtocolContractState;
use std::future::Future;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "network-hardship-simulation")]
use std::time::Duration;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "network-hardship-simulation")]
pub async fn check_block_processing(process_blocks_sender: watch::Sender<bool>, home_dir: PathBuf) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let new_val = match load_listening_blocks_file(&home_dir) {
            Ok(new_val) => {
                tracing::info!("flag file found, setting to {}", new_val);
                new_val
            }
            Err(e) => {
                tracing::info!("flag file not found, setting to {}. Error: {}", true, e);
                true
            }
        };
        if process_blocks_sender.send(new_val).is_err() {
            tracing::info!("channel closed");
            return;
        }
    }
}

/// Wires nearcore's shutdown signal so that a [`ShutdownReason::EpochSyncDataReset`]
/// is acted on instead of dropped: a stale node that would otherwise loop forever in
/// epoch-sync (#3909) records the reset marker and asks the node to shut down, so the
/// container's `restart: on-failure` brings it back and the startup wipe runs.
///
/// The reset goes through `reset_shutdown` so the node's graceful teardown runs
/// (committing in-flight SecretDB batches) before the non-zero exit. Returns the sender
/// to pass to [`nearcore::start_with_config_and_synchronization`].
///
/// `restart_disabled` suppresses the restart when a wipe must not (or cannot) run — an
/// archival node, or a startup wipe that just failed — so the reset can only wedge the
/// node, never restart-loop it. Its message names the reason for the operator.
fn spawn_epoch_sync_reset_handler(
    home_dir: PathBuf,
    restart_disabled: Option<&'static str>,
    reset_shutdown: mpsc::Sender<()>,
) -> broadcast::Sender<ShutdownReason> {
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<ShutdownReason>(16);
    tokio::spawn(async move {
        // Loop rather than a single `recv`: nearcore currently sends at most one reason,
        // but not relying on that means a future reordering (e.g. an `ExpectedShutdown`
        // ahead of the reset) can't silently eat the signal this handler exists to catch.
        while handle_shutdown_signal(
            shutdown_rx.recv().await,
            &home_dir,
            restart_disabled,
            &reset_shutdown,
        )
        .await
        .is_continue()
        {}
    });
    shutdown_tx
}

/// Handles one nearcore shutdown signal. Returns [`ControlFlow::Break`] once the handler
/// is done — a restart was requested, or the channel closed — and [`ControlFlow::Continue`]
/// to keep listening.
async fn handle_shutdown_signal(
    signal: Result<ShutdownReason, broadcast::error::RecvError>,
    home_dir: &Path,
    restart_disabled: Option<&str>,
    reset_shutdown: &mpsc::Sender<()>,
) -> ControlFlow<()> {
    match signal {
        Ok(ShutdownReason::EpochSyncDataReset) => {
            if let Some(reason) = restart_disabled {
                tracing::error!(
                    "epoch-sync data reset requested but {reason}; not restarting — \
                     manual recovery required"
                );
                return ControlFlow::Continue(());
            }
            tracing::warn!(
                "epoch-sync data reset requested; recording marker and restarting \
                 to wipe the chain store"
            );
            // Only request the restart once the marker is on disk; otherwise a persistent
            // write failure (full or read-only fs) would restart-loop with nothing to
            // break it. Stay up wedged instead.
            match record_epoch_sync_reset_request(home_dir) {
                Ok(()) => {
                    let _ = reset_shutdown.send(()).await;
                    ControlFlow::Break(())
                }
                Err(err) => {
                    tracing::error!(
                        ?err,
                        "could not record the epoch-sync reset marker; staying up wedged"
                    );
                    ControlFlow::Continue(())
                }
            }
        }
        // mpc-node does not configure `expected_shutdown`, so ignore it rather than take
        // the node offline.
        Ok(ShutdownReason::ExpectedShutdown) => {
            tracing::warn!("nearcore signalled ExpectedShutdown; ignoring");
            ControlFlow::Continue(())
        }
        Err(broadcast::error::RecvError::Lagged(skipped)) => {
            tracing::warn!(
                skipped,
                "shutdown-signal receiver lagged; may have missed a reset"
            );
            ControlFlow::Continue(())
        }
        // Closed is the normal teardown path; nothing to do.
        Err(broadcast::error::RecvError::Closed) => ControlFlow::Break(()),
    }
}

/// Spawns a real indexer, returning a handle to the indexer, [`IndexerAPI`].
///
/// If an unrecoverable error occurs, the spawned indexer will terminate, and the provided [`oneshot::Sender`]
/// will be used to propagate the error.
#[expect(clippy::too_many_arguments)]
pub fn spawn_real_indexer(
    home_dir: PathBuf,
    mpc_indexer_config: IndexerConfig,
    my_near_account_id: AccountId,
    account_secret_key: SigningKey,
    respond_config: RespondConfig,
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
    // Fired on `EpochSyncDataReset` so the main loop shuts down gracefully and exits
    // non-zero (see `spawn_epoch_sync_reset_handler`).
    epoch_reset_shutdown: mpsc::Sender<()>,
    protocol_state_sender: watch::Sender<ProtocolContractState>,
    migration_state_sender: watch::Sender<(u64, ContractMigrationInfo)>,
    tls_public_key: VerifyingKey,
    foreign_chains: mpc_node_config::ForeignChainsConfig,
    tx_logger: impl LogTransaction,
    shutdown_token: CancellationToken,
) -> IndexerAPI<impl TransactionSender> {
    let (contract_state_sender_oneshot, contract_state_receiver_oneshot) = oneshot::channel();
    let (migration_info_sender_oneshot, migration_info_receiver_oneshot) = oneshot::channel();
    let (foreign_chain_supporters_sender_oneshot, foreign_chain_supporters_receiver_oneshot) =
        oneshot::channel();
    let (attestation_reader_sender, attestation_reader_receiver) = oneshot::channel();

    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (allowed_docker_images_sender, allowed_docker_images_receiver) = watch::channel(vec![]);
    let (allowed_launcher_compose_sender, allowed_launcher_compose_receiver) =
        watch::channel(vec![]);

    let my_near_account_id_clone = my_near_account_id.clone();
    let respond_config_clone = respond_config.clone();

    let (txn_sender_sender, txn_sender_receiver) = oneshot::channel();

    std::thread::spawn(move || {
        // TODO(#1515): limit number of worker threads? Assume not as we don't want the node to fall behind
        let indexer_tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime must be constructable on startup");

        // TODO(#1515): Clean this entire function up eventually.
        // We have this indirection of using a oneshot for sending the indexer state,
        // as we can't block the main thread for waiting on the `txn_sender`.
        // Thus we instead initialize a `txn_sender`, which runs as a spawned task, to await on the indexer state being ready.
        indexer_tokio_runtime.block_on(async {
            let near_indexer_config = mpc_indexer_config.to_near_indexer_config(home_dir.clone());

            let near_config = near_indexer_config
                .load_near_config()
                .expect("near config is present");

            // Operator-driven one-time wipe: when `wipe_near_data_token` is non-zero
            // and differs from the last applied value, wipe the data dir. Must run
            // here, after the config is loaded but before nearcore opens the store
            // below, because the dir can't be removed while nearcore holds it open.
            // Runs once per process start, so a changed token takes effect on the
            // next restart.
            let hot_store_path = match near_config.config.store.path.as_deref() {
                Some(path) => home_dir.join(path),
                None => near_data_dir(&home_dir),
            };
            wipe_near_data_if_requested(
                &home_dir,
                &hot_store_path,
                mpc_indexer_config.wipe_near_data_token,
                near_config.client_config.archive,
            )
            .expect(
                "wipe_near_data_token is set but wiping the nearcore data dir failed, \
                 fix the cause and set wipe_near_data_token to a new value to retry",
            );

            // If nearcore requested an epoch-sync data reset on a previous run, wipe the
            // chain store before it reopens (see #3909). A hard failure here must not
            // panic — that would crash-loop with the marker still on disk. Surface an
            // actionable error and remember it, so the reset handler below is disarmed
            // and the node wedges rather than restart-loops on a wipe that keeps failing.
            let reset_wipe_failed = wipe_near_data_if_epoch_sync_reset(
                &home_dir,
                &hot_store_path,
                near_config.client_config.archive,
            )
            .inspect_err(|err| {
                tracing::error!(
                    ?err,
                    marker = ?epoch_sync_reset_marker_file(&home_dir),
                    "epoch-sync data-reset wipe failed; not restarting to avoid a wipe \
                     loop — resolve the cause or delete the marker manually",
                );
            })
            .is_err();

            let restart_disabled = if near_config.client_config.archive {
                Some("node is archival (auto-wipe would destroy the archive)")
            } else if reset_wipe_failed {
                Some("the previous epoch-sync wipe failed")
            } else {
                None
            };
            let shutdown_tx = spawn_epoch_sync_reset_handler(
                home_dir.clone(),
                restart_disabled,
                epoch_reset_shutdown,
            );

            let near_node = nearcore::start_with_config_and_synchronization(
                &home_dir,
                near_config.clone(),
                ActorSystem::new(),
                Some(shutdown_tx),
                None,
            )
            .await
            .expect("near node has started");

            let indexer = Indexer::from_near_node(near_indexer_config, near_config, &near_node);

            let indexer_state = Arc::new(IndexerState::new(
                near_node.view_client,
                near_node.client,
                near_node.rpc_handler,
                mpc_indexer_config.mpc_contract_id.clone(),
            ));

            tracing::info!("Indexer waiting for node to finish syncing before streaming blocks.");

            // Streaming before the node is synced pins the `LatestSynced` cursor
            // at genesis, below the block tail it can never reach. Raced against
            // shutdown so a SIGTERM during state sync still tears down cleanly.
            if !await_sync_or_shutdown(
                indexer_state.client.ensure_head_follows_tip(),
                &shutdown_token,
            )
            .await
            {
                tracing::info!(
                    "Indexer thread received shutdown signal before sync completed; exiting."
                );
                let _ = indexer_exit_sender.send(Ok(()));
                return;
            }

            // The node is fully synced by this point, so `LatestSynced` resolves
            // to the chain tip rather than genesis.
            let stream = indexer.streamer();

            let txn_sender_result = TransactionProcessorHandle::start_transaction_processor(
                my_near_account_id_clone,
                account_secret_key.clone(),
                respond_config_clone,
                Arc::clone(&indexer_state),
                tx_logger,
            );

            let Ok(txn_sender) = txn_sender_result else {
                tracing::error!("Failed to start transaction processor. Exiting indexer.");
                let _ = indexer_exit_sender.send(txn_sender_result.map(|_| ()));
                return;
            };

            if txn_sender_sender.send(txn_sender).is_err() {
                tracing::error!("Failed to send txn_sender back to main thread.")
            };

            let attestation_reader: std::sync::Arc<dyn super::ReadAttestationExpiry> =
                std::sync::Arc::new(RealAttestationExpiryReader::new(indexer_state.clone()));
            if attestation_reader_sender.send(attestation_reader).is_err() {
                tracing::error!("failed to send attestation reader back to main thread")
            };

            #[cfg(feature = "network-hardship-simulation")]
            let process_blocks_receiver = {
                let (process_blocks_sender, process_blocks_receiver) = watch::channel(true);
                tokio::spawn(check_block_processing(process_blocks_sender, home_dir));
                process_blocks_receiver
            };

            tokio::spawn(indexer_logger(Arc::clone(&indexer_state)));

            tokio::spawn(monitor_allowed_docker_images(
                allowed_docker_images_sender,
                indexer_state.clone(),
            ));

            tokio::spawn(monitor_allowed_launcher_compose_hashes(
                allowed_launcher_compose_sender,
                indexer_state.clone(),
            ));

            let foreign_chain_supporters_receiver =
                monitor_foreign_chain_supporters(indexer_state.clone()).await;
            if foreign_chain_supporters_sender_oneshot
                .send(foreign_chain_supporters_receiver)
                .is_err()
            {
                tracing::error!(
                    "Indexer thread could not send foreign chain supporters receiver back to main driver."
                )
            };

            let (foreign_chain_whitelist_sender, foreign_chain_whitelist_receiver) =
                watch::channel(std::collections::BTreeMap::new());
            tokio::spawn(monitor_allowed_foreign_chain_providers(
                foreign_chain_whitelist_sender,
                indexer_state.clone(),
            ));
            tokio::spawn(crate::foreign_chain_whitelist_verifier::run(
                foreign_chain_whitelist_receiver,
                foreign_chains.clone(),
            ));

            // Returns once the contract state is available.
            let contract_state_receiver = monitor_contract_state(
                indexer_state.clone(),
                mpc_indexer_config.port_override,
                protocol_state_sender,
            )
            .await;

            if contract_state_sender_oneshot
                .send(contract_state_receiver)
                .is_err()
            {
                tracing::error!(
                    "Indexer thread could not send contract state receiver back to main driver."
                )
            };

            let my_migration_info_receiver = monitor_migrations(
                indexer_state.clone(),
                migration_state_sender,
                my_near_account_id,
                tls_public_key,
            )
            .await;

            if migration_info_sender_oneshot
                .send(my_migration_info_receiver)
                .is_err()
            {
                tracing::error!(
                    "Indexer thread could not send migration info receiver back to main driver."
                )
            };

            // `listen_blocks` runs indefinitely and only returns in case of an
            // error. To shut the indexer thread down cleanly on SIGTERM we
            // race it against `shutdown_token.cancelled()`: when the parent
            // cancels the token, the select! arm completes, `block_on`
            // returns, the indexer's tokio runtime drops, and every
            // `tokio::spawn`'d monitor task (each holding
            // `Arc<IndexerState>` → `Arc<RocksDB>`) is aborted as the
            // runtime is dropped. That's what lets
            // `RocksDB::block_until_all_instances_are_dropped()` in `run.rs`
            // actually return on the SIGTERM path.
            #[cfg(feature = "network-hardship-simulation")]
            let indexer_result = tokio::select! {
                res = listen_blocks(
                    stream,
                    mpc_indexer_config.concurrency,
                    Arc::clone(&indexer_state.stats),
                    mpc_indexer_config.mpc_contract_id,
                    block_update_sender,
                    process_blocks_receiver,
                ) => res,
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Indexer thread received shutdown signal; exiting listen_blocks.");
                    Ok(())
                }
            };

            #[cfg(not(feature = "network-hardship-simulation"))]
            let indexer_result = tokio::select! {
                res = listen_blocks(
                    stream,
                    mpc_indexer_config.concurrency,
                    Arc::clone(&indexer_state.stats),
                    mpc_indexer_config.mpc_contract_id,
                    block_update_sender,
                ) => res,
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Indexer thread received shutdown signal; exiting listen_blocks.");
                    Ok(())
                }
            };

            if indexer_exit_sender.send(indexer_result).is_err() {
                tracing::error!("Indexer thread could not send result back to main driver.")
            };
        });
    });

    let txn_sender = txn_sender_receiver
        .blocking_recv()
        .expect("txn_sender is returned from the `block_on` expression above.");

    let contract_state_receiver = contract_state_receiver_oneshot
        .blocking_recv()
        .expect("Contract state receiver must be returned by indexer.");

    let my_migration_info_receiver = migration_info_receiver_oneshot
        .blocking_recv()
        .expect("Migraration info receiver must be returned by indexer.");

    let foreign_chain_supporters_receiver = foreign_chain_supporters_receiver_oneshot
        .blocking_recv()
        .expect("foreign chain supporters receiver must be returned by indexer");

    let attestation_reader = attestation_reader_receiver
        .blocking_recv()
        .expect("attestation reader must be returned by indexer");

    IndexerAPI {
        contract_state_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender,
        allowed_docker_images_receiver,
        allowed_launcher_compose_receiver,
        my_migration_info_receiver,
        foreign_chain_supporters_receiver,
        attestation_reader,
    }
}

async fn await_sync_or_shutdown(
    sync: impl Future<Output = ()>,
    shutdown: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = sync => true,
        _ = shutdown.cancelled() => false,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{ShutdownReason, await_sync_or_shutdown, handle_shutdown_signal};
    use crate::home_paths::epoch_sync_reset_marker_file;
    use std::future::pending;
    use std::ops::ControlFlow;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn await_sync_or_shutdown__should_return_true_when_sync_completes_first() {
        // Given
        let shutdown = CancellationToken::new();

        // When
        let synced = await_sync_or_shutdown(async {}, &shutdown).await;

        // Then
        assert!(synced);
    }

    /// The dominant production path: a SIGTERM arrives while the node is still
    /// syncing, so the wait must yield to shutdown rather than block on sync.
    #[tokio::test]
    async fn await_sync_or_shutdown__should_return_false_when_shutdown_during_sync() {
        // Given
        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move { shutdown_clone.cancel() });

        // When
        let synced = await_sync_or_shutdown(pending::<()>(), &shutdown).await;

        // Then
        assert!(!synced);
    }

    #[tokio::test]
    async fn handle_shutdown_signal__should_record_marker_and_request_restart_on_reset() {
        // Given
        let home = tempfile::tempdir().unwrap();
        let (reset_tx, mut reset_rx) = mpsc::channel(1);

        // When
        let flow = handle_shutdown_signal(
            Ok(ShutdownReason::EpochSyncDataReset),
            home.path(),
            None,
            &reset_tx,
        )
        .await;

        // Then
        assert_eq!(flow, ControlFlow::Break(()));
        assert!(epoch_sync_reset_marker_file(home.path()).exists());
        assert_eq!(reset_rx.try_recv(), Ok(()));
    }

    #[tokio::test]
    async fn handle_shutdown_signal__should_not_restart_or_mark_when_restart_disabled() {
        // Given
        let home = tempfile::tempdir().unwrap();
        let (reset_tx, mut reset_rx) = mpsc::channel(1);

        // When
        let flow = handle_shutdown_signal(
            Ok(ShutdownReason::EpochSyncDataReset),
            home.path(),
            Some("node is archival"),
            &reset_tx,
        )
        .await;

        // Then
        assert_eq!(flow, ControlFlow::Continue(()));
        assert!(!epoch_sync_reset_marker_file(home.path()).exists());
        assert!(reset_rx.try_recv().is_err());
    }
}
