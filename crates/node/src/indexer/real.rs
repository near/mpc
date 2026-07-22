use super::foreign_chain::monitor_foreign_chain_supporters;
use super::handler::listen_blocks;
use super::migrations::{ContractMigrationInfo, monitor_migrations};
use super::near_data_wipe::wipe_near_data_if_requested;
use super::participants::monitor_contract_state;
use super::stats::indexer_logger;
use super::{IndexerAPI, IndexerState, RealForeignChainPolicyReader};
use crate::config::RespondConfig;
#[cfg(feature = "network-hardship-simulation")]
use crate::config::load_listening_blocks_file;
use crate::home_paths::near_data_dir;
use crate::indexer::configs::IndexerConfigExt;
use crate::indexer::tee::{
    monitor_allowed_docker_images, monitor_allowed_foreign_chain_providers,
    monitor_allowed_launcher_compose_hashes, monitor_tee_accounts,
};
use crate::indexer::tx_sender::TransactionProcessorHandle;
use crate::types::LogTransaction;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_node_config::IndexerConfig;
use near_account_id::AccountId;
use near_async::ActorSystem;
use near_indexer::Indexer;
use near_mpc_contract_interface::types::ProtocolContractState;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "network-hardship-simulation")]
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
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

/// Spawns a real indexer, returning a handle to the indexer, [`IndexerApi`].
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
    protocol_state_sender: watch::Sender<ProtocolContractState>,
    migration_state_sender: watch::Sender<(u64, ContractMigrationInfo)>,
    tls_public_key: VerifyingKey,
    foreign_chains: mpc_node_config::ForeignChainsConfig,
    tx_logger: impl LogTransaction,
    shutdown_token: CancellationToken,
) -> IndexerAPI<TransactionProcessorHandle, RealForeignChainPolicyReader> {
    let (contract_state_sender_oneshot, contract_state_receiver_oneshot) = oneshot::channel();
    let (migration_info_sender_oneshot, migration_info_receiver_oneshot) = oneshot::channel();
    let (foreign_chain_policy_reader_sender, foreign_chain_policy_reader_receiver) =
        oneshot::channel();
    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (allowed_docker_images_sender, allowed_docker_images_receiver) = watch::channel(vec![]);
    let (allowed_launcher_compose_sender, allowed_launcher_compose_receiver) =
        watch::channel(vec![]);
    let (tee_accounts_sender, tee_accounts_receiver) = watch::channel(vec![]);
    let (foreign_chain_supporters_sender, foreign_chain_supporters_receiver) =
        watch::channel(Default::default());

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
            // here, after the config is loaded but before `start_near_node` below
            // opens the store, because the dir can't be removed while nearcore holds
            // it open. Runs once per process start, so a changed token takes effect on
            // the next restart.
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

            let near_node = Indexer::start_near_node(
                &near_indexer_config,
                near_config.clone(),
                ActorSystem::new(),
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

            let foreign_chain_policy_reader =
                RealForeignChainPolicyReader::new(indexer_state.clone());
            if foreign_chain_policy_reader_sender
                .send(foreign_chain_policy_reader)
                .is_err()
            {
                tracing::error!("failed to send foreign chain policy reader back to main thread")
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

            tokio::spawn(monitor_tee_accounts(
                tee_accounts_sender,
                indexer_state.clone(),
            ));

            tokio::spawn(monitor_foreign_chain_supporters(
                foreign_chain_supporters_sender,
                indexer_state.clone(),
            ));

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

    let foreign_chain_policy_reader = foreign_chain_policy_reader_receiver
        .blocking_recv()
        .expect("foreign chain policy reader must be returned by indexer");

    IndexerAPI {
        contract_state_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender,
        allowed_docker_images_receiver,
        allowed_launcher_compose_receiver,
        attested_nodes_receiver: tee_accounts_receiver,
        my_migration_info_receiver,
        foreign_chain_policy_reader,
        foreign_chain_supporters_receiver,
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
    use super::await_sync_or_shutdown;
    use std::future::pending;
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
}
