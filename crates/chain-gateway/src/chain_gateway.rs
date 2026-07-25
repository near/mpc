use std::future::Future;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::errors::{ChainGatewayError, NearClientError, NearRpcError, NearViewClientError};
use crate::event_subscriber;
use crate::event_subscriber::block_events::BlockUpdate;
use crate::event_subscriber::streamer::StreamerConfig;
use crate::event_subscriber::subscriber::BlockEventSubscriptions;
use crate::near_internals_wrapper::{
    NearClientActorHandle, NearRpcActorHandle, NearViewClientActorHandle,
};
use crate::primitives::{FetchLatestFinalBlockInfo, IsSyncing, SubmitSignedTransaction};
use near_account_id::AccountId;
use near_async::ActorSystem;
use near_client::client_actor::ShutdownReason;
use near_contract_transport::{BlockHeight, ObservedState};
use near_contract_transport::{ViewArgs, ViewContract};
use near_indexer::StreamerMessage;
use near_indexer::near_primitives::transaction::SignedTransaction;
use nearcore::NearConfig;
use tokio::sync::mpsc::Receiver;

const EPOCH_SYNC_DATA_RESET_MARKER_FILE_NAME: &str = ".EPOCH_SYNC_DATA_RESET";

struct SharedHandles {
    view_client: RwLock<NearViewClientActorHandle>,
    client: RwLock<NearClientActorHandle>,
    rpc_handler: RwLock<NearRpcActorHandle>,
}

impl SharedHandles {
    fn new(
        view_client: NearViewClientActorHandle,
        client: NearClientActorHandle,
        rpc_handler: NearRpcActorHandle,
    ) -> Self {
        Self {
            view_client: RwLock::new(view_client),
            client: RwLock::new(client),
            rpc_handler: RwLock::new(rpc_handler),
        }
    }

    fn view_client(&self) -> NearViewClientActorHandle {
        self.view_client
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn client(&self) -> NearClientActorHandle {
        self.client
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn rpc_handler(&self) -> NearRpcActorHandle {
        self.rpc_handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn replace(
        &self,
        view_client: NearViewClientActorHandle,
        client: NearClientActorHandle,
        rpc_handler: NearRpcActorHandle,
    ) {
        *self
            .view_client
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = view_client;
        *self
            .client
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = client;
        *self
            .rpc_handler
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = rpc_handler;
    }
}

#[derive(Clone)]
pub struct ChainGateway {
    handles: Arc<SharedHandles>,
}

impl IsSyncing for ChainGateway {
    type Error = NearClientError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.handles.client().is_syncing().await
    }
}

impl ViewContract for ChainGateway {
    type Error = NearViewClientError;
    type ObservedAt = BlockHeight;
    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        self.handles
            .view_client()
            .view_contract(contract_id, view_args)
            .await
    }
}

impl FetchLatestFinalBlockInfo for ChainGateway {
    type Error = NearViewClientError;
    async fn fetch_latest_final_block_info(
        &self,
    ) -> Result<crate::types::LatestFinalBlockInfo, Self::Error> {
        self.handles
            .view_client()
            .fetch_latest_final_block_info()
            .await
    }
}

impl SubmitSignedTransaction for ChainGateway {
    type Error = NearRpcError;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error> {
        self.handles
            .rpc_handler()
            .submit_signed_transaction(transaction)
            .await
    }
}

/// Handle to the background thread running the nearcore node.
///
/// Provides liveness checking via [`is_node_alive`](Self::is_node_alive) and
/// shutdown via [`send_shutdown`](Self::send_shutdown). A stale node that
/// can't sync forward is recovered automatically, in-process, without
/// affecting either of these; `is_node_alive` only goes false and
/// `send_shutdown` is only needed for a deliberate, caller-initiated stop.
pub struct NodeHandle {
    thread_handle: std::thread::JoinHandle<()>,
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl NodeHandle {
    /// Returns `true` if the nearcore background thread is still running.
    pub fn is_node_alive(&self) -> bool {
        !self.thread_handle.is_finished()
    }

    /// Sends the shutdown signal to the nearcore node.
    /// Returns `true` if the signal was sent, `false` if already sent or node already dead.
    pub fn send_shutdown(&mut self) -> bool {
        self.shutdown_sender
            .take()
            .map(|tx| tx.send(()).is_ok())
            .unwrap_or(false)
    }
}

impl ChainGateway {
    /// Spawns a near node with `indexer_config`.
    /// The [`NodeHandle`] can be used to shut down the actor system for the node and liveness checks.
    /// The node dies if [`NodeHandle`] is dropped.
    /// Returns a stream for BlockUpdates if BlockEventSubscriptions is not None.
    ///
    /// If the node falls stale and can't sync forward, it is automatically wiped and restarted
    /// in-process; this `ChainGateway` transparently keeps working across that restart.
    pub async fn start(
        indexer_config: near_indexer::IndexerConfig,
        subscriber: Option<BlockEventSubscriptions>,
    ) -> Result<(ChainGateway, NodeHandle, Option<Receiver<BlockUpdate>>), ChainGatewayError> {
        let near_config: NearConfig = indexer_config.load_near_config().map_err(|err| {
            ChainGatewayError::FailureLoadingConfig {
                msg: err.to_string(),
            }
        })?;

        let home_dir = indexer_config.home_dir.clone();
        let streamer_setup = subscriber.map(|subscriber| StreamerSetup {
            subscriber,
            indexer_config,
            near_config: near_config.clone(),
        });

        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        let thread_handle = std::thread::spawn(move || {
            run_node(
                ready_sender,
                near_config,
                &home_dir,
                shutdown_receiver,
                streamer_setup,
            )
        });

        let (chain_gateway, stream) = ready_receiver.await.expect("startup thread died")?;
        let node_handle = NodeHandle {
            thread_handle,
            shutdown_sender: Some(shutdown_sender),
        };
        Ok((chain_gateway, node_handle, stream))
    }
}

type RunNodeResult = Result<(ChainGateway, Option<Receiver<BlockUpdate>>), ChainGatewayError>;

struct RunningState {
    actor_system: ActorSystem,
    rx_crash: tokio::sync::broadcast::Receiver<ShutdownReason>,
}

/// Checks for a leftover epoch-sync-data-reset marker and wipes the store if
/// present (mirrors `neard::cli::check_epoch_sync_data_reset_marker`), then
/// starts the nearcore node.
async fn start_node(
    home_dir: &Path,
    near_config: NearConfig,
    hot_store_path: &Path,
) -> Result<(RunningState, nearcore::NearNode), ChainGatewayError> {
    check_epoch_sync_data_reset_marker(hot_store_path)?;

    let (tx_crash, rx_crash) = tokio::sync::broadcast::channel::<ShutdownReason>(16);
    let actor_system = ActorSystem::new();
    let near_node = nearcore::start_with_config_and_synchronization(
        home_dir,
        near_config,
        actor_system.clone(),
        Some(tx_crash),
        None,
    )
    .await
    .map_err(|err| ChainGatewayError::StartupFailed {
        msg: err.to_string(),
    })?;

    Ok((
        RunningState {
            actor_system,
            rx_crash,
        },
        near_node,
    ))
}

fn wrap_handles(
    near_node: nearcore::NearNode,
) -> (
    NearViewClientActorHandle,
    NearClientActorHandle,
    NearRpcActorHandle,
) {
    (
        NearViewClientActorHandle::new(near_node.view_client),
        NearClientActorHandle::new(near_node.client),
        NearRpcActorHandle::new(near_node.rpc_handler),
    )
}

fn run_node(
    ready_sender: tokio::sync::oneshot::Sender<RunNodeResult>,
    near_config: NearConfig,
    home_dir: &Path,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    streamer_setup: Option<StreamerSetup>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime must be constructable on startup");

    rt.block_on(async move {
        let hot_store_path = home_dir
            .join(near_config.config.store.path.as_deref().unwrap_or_else(|| Path::new("data")));

        let (mut running_state, near_node) =
            match start_node(home_dir, near_config.clone(), &hot_store_path).await {
                Ok(g) => g,
                Err(err) => {
                    let _ = ready_sender.send(Err(err));
                    return;
                }
            };

        let indexer_and_params = streamer_setup.map(|s| {
            let indexer = near_indexer::Indexer::from_near_node(
                s.indexer_config.clone(),
                s.near_config,
                &near_node,
            );
            (indexer, s.indexer_config, s.subscriber)
        });

        let (view_client, client, rpc_handler) = wrap_handles(near_node);

        let mut streaming_state: Option<StreamingState> = None;

        let stream = if let Some((indexer, indexer_config, streamer_config)) = indexer_and_params {
            // Don't start the streamer until synced, or its `LatestSynced`
            // cursor pins at genesis. Raced against shutdown to stay responsive.
            tracing::info!(
                "chain-gateway waiting for node to finish syncing before streaming blocks."
            );
            let synced = await_sync_or_shutdown(client.wait_for_full_sync(), async {
                let _ = (&mut shutdown_receiver).await;
            }).await;
            if !synced {
                tracing::info!("shutdown requested before sync completed; exiting startup.");
                let _ = ready_sender.send(Err(ChainGatewayError::StartupFailed {
                    msg: "shutdown requested before node finished syncing".to_string(),
                }));
                running_state.actor_system.stop();
                return;
            }

            let raw_stream: Receiver<StreamerMessage> = indexer.streamer();
            match event_subscriber::streamer::start(
                streamer_config,
                raw_stream,
                view_client.clone(),
            ).await
            {
                Ok(started) => {
                    streaming_state = Some(StreamingState {
                        indexer_config,
                        streamer_config: started.config,
                        block_tx: started.block_tx,
                    });
                    Some(started.block_rx)
                }
                Err(err) => {
                    let _ = ready_sender.send(Err(err));
                    return;
                }
            }
        } else {
            None
        };

        let handles = Arc::new(SharedHandles::new(
            view_client.clone(),
            client.clone(),
            rpc_handler.clone(),
        ));

        let _ = ready_sender.send(Ok((
            ChainGateway {
                handles: handles.clone(),
            },
            stream,
        )));

        loop {
            tokio::select! {
                result = &mut shutdown_receiver => {
                    match result {
                        Ok(()) => tracing::info!("node gracefully shutting down actor system"),
                        Err(_) => tracing::info!("shutdown sender was dropped, shutting down actor system"),
                    }
                    running_state.actor_system.stop();
                    return;
                }
                result = running_state.rx_crash.recv() => {
                    match result {
                        Ok(ShutdownReason::EpochSyncDataReset) => {
                            tracing::warn!(
                                "node fell too far behind to sync via epoch sync; wiping data \
                                 directory and restarting the node in-process"
                            );
                            if let Err(err) = write_epoch_sync_data_reset_marker(&hot_store_path) {
                                tracing::error!(
                                    ?err,
                                    "failed to write epoch sync data reset marker; aborting \
                                     restart rather than looping back into the same stale state"
                                );
                                running_state.actor_system.stop();
                                return;
                            }
                            running_state.actor_system.stop();

                            match start_node(home_dir, near_config.clone(), &hot_store_path).await {
                                Ok((new_running_state, new_near_node)) => {
                                    let reconnect_stream = streaming_state.as_ref().map(|state| {
                                        near_indexer::Indexer::from_near_node(
                                            state.indexer_config.clone(),
                                            near_config.clone(),
                                            &new_near_node,
                                        )
                                        .streamer()
                                    });

                                    let (new_view_client, new_client, new_rpc_handler) =
                                        wrap_handles(new_near_node);

                                    if let (Some(raw_stream), Some(state)) =
                                        (reconnect_stream, streaming_state.as_ref())
                                    {
                                        event_subscriber::streamer::reconnect(
                                            state.streamer_config.clone(),
                                            raw_stream,
                                            new_view_client.clone(),
                                            state.block_tx.clone(),
                                        );
                                        tracing::info!("reconnected block-event stream to restarted node");
                                    }

                                    handles.replace(new_view_client, new_client, new_rpc_handler);
                                    running_state = new_running_state;
                                    tracing::info!("node restarted and recovered after epoch sync data reset");
                                }
                                Err(err) => {
                                    tracing::error!(
                                        ?err,
                                        "failed to restart node after epoch sync data reset; \
                                         node handle is now dead and will not retry further"
                                    );
                                    return;
                                }
                            }
                        }
                        Ok(other_reason) => {
                            tracing::info!(?other_reason, "node requested shutdown for a reason other than epoch sync data reset");
                            running_state.actor_system.stop();
                            return;
                        }
                        Err(_) => {
                            tracing::warn!("nearcore shutdown-signal channel closed unexpectedly; stopping node");
                            running_state.actor_system.stop();
                            return;
                        }
                    }
                }
            }
        }
    });
}

/// Mirrors `neard::cli::check_epoch_sync_data_reset_marker`: if a previous run
/// left the reset marker behind, wipe the data directory before starting.
fn check_epoch_sync_data_reset_marker(hot_store_path: &Path) -> Result<(), ChainGatewayError> {
    let marker_path = hot_store_path.join(EPOCH_SYNC_DATA_RESET_MARKER_FILE_NAME);
    if !marker_path.exists() {
        return Ok(());
    } else {
        tracing::info!(
            ?hot_store_path,
            "epoch sync data reset marker found, deleting data directory"
        );
        std::fs::remove_dir_all(hot_store_path).map_err(|err| {
            ChainGatewayError::StartupFailed {
                msg: format!("failed to delete data directory for epoch sync reset: {err}"),
            }
        })?;
    }
    Ok(())
}

/// Mirrors `neard::cli::write_epoch_sync_data_reset_marker`.
fn write_epoch_sync_data_reset_marker(hot_store_path: &Path) -> std::io::Result<()> {
    let marker_path = hot_store_path.join(EPOCH_SYNC_DATA_RESET_MARKER_FILE_NAME);
    std::fs::create_dir_all(hot_store_path)?;
    std::fs::write(&marker_path, b"")?;
    std::fs::File::open(&marker_path)?.sync_all()?;
    std::fs::File::open(hot_store_path)?.sync_all()?;
    Ok(())
}

/// Parameters for optionally starting the block-event streaming pipeline
/// alongside the nearcore node.
struct StreamerSetup {
    subscriber: BlockEventSubscriptions,
    indexer_config: near_indexer::IndexerConfig,
    near_config: NearConfig,
}

struct StreamingState {
    indexer_config: near_indexer::IndexerConfig,
    streamer_config: StreamerConfig,
    block_tx: tokio::sync::mpsc::Sender<BlockUpdate>,
}

async fn await_sync_or_shutdown(
    sync: impl Future<Output = ()>,
    shutdown: impl Future<Output = ()>,
) -> bool {
    tokio::select! {
        _ = sync => true,
        _ = shutdown => false,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::await_sync_or_shutdown;
    use std::future::pending;

    #[tokio::test]
    async fn await_sync_or_shutdown__should_return_true_when_sync_completes_first() {
        // Given
        let sync = async {};
        let shutdown = pending::<()>();

        // When
        let synced = await_sync_or_shutdown(sync, shutdown).await;

        // Then
        assert!(synced);
    }

    /// A shutdown (or abandoned startup) arriving while the node is still
    /// syncing must win the race rather than block on sync.
    #[tokio::test]
    async fn await_sync_or_shutdown__should_return_false_when_shutdown_first() {
        // Given
        let sync = pending::<()>();
        let shutdown = async {};

        // When
        let synced = await_sync_or_shutdown(sync, shutdown).await;

        // Then
        assert!(!synced);
    }
}
