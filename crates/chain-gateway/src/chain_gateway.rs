use std::future::Future;
use std::path::Path;

use near_account_id::AccountId;
use near_async::ActorSystem;
use near_indexer::StreamerMessage;
use near_indexer::near_primitives::transaction::SignedTransaction;
use nearcore::NearConfig;
use tokio::sync::mpsc::Receiver;

use crate::errors::{ChainGatewayError, NearClientError, NearRpcError, NearViewClientError};
use crate::event_subscriber;
use crate::event_subscriber::block_events::BlockUpdate;
use crate::event_subscriber::subscriber::BlockEventSubscriptions;
use crate::near_internals_wrapper::{
    NearClientActorHandle, NearRpcActorHandle, NearViewClientActorHandle,
};
use crate::primitives::{
    FetchLatestFinalBlockInfo, IsSyncing, QueryViewFunction, SubmitSignedTransaction, SyncStatus,
};
use crate::types::ObservedState;

#[derive(Clone)]
pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: NearViewClientActorHandle,
    /// For querying blockchain sync status.
    client: NearClientActorHandle,
    /// For sending transactions to the blockchain.
    rpc_handler: NearRpcActorHandle,
}

impl IsSyncing for ChainGateway {
    type Error = NearClientError;
    async fn sync_status(&self) -> Result<SyncStatus, Self::Error> {
        self.client.sync_status().await
    }
}

impl QueryViewFunction for ChainGateway {
    type Error = NearViewClientError;
    async fn query_view_function(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, Self::Error> {
        self.view_client
            .query_view_function(contract_id, method_name, args)
            .await
    }
}

impl FetchLatestFinalBlockInfo for ChainGateway {
    type Error = NearViewClientError;
    async fn fetch_latest_final_block_info(
        &self,
    ) -> Result<crate::types::LatestFinalBlockInfo, Self::Error> {
        self.view_client.fetch_latest_final_block_info().await
    }
}

impl SubmitSignedTransaction for ChainGateway {
    type Error = NearRpcError;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error> {
        self.rpc_handler
            .submit_signed_transaction(transaction)
            .await
    }
}

/// Handle to the background thread running the nearcore node.
///
/// Provides liveness checking via [`is_node_alive`](Self::is_node_alive) and
/// shutdown via [`send_shutdown`](Self::send_shutdown).
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
    pub async fn start(
        indexer_config: near_indexer::IndexerConfig,
        subscriber: Option<BlockEventSubscriptions>,
    ) -> Result<
        (
            ChainGateway,
            NodeHandle,
            Option<tokio::sync::mpsc::Receiver<BlockUpdate>>,
        ),
        ChainGatewayError,
    > {
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

fn run_node(
    ready_sender: tokio::sync::oneshot::Sender<RunNodeResult>,
    near_config: nearcore::NearConfig,
    home_dir: &Path,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    streamer_setup: Option<StreamerSetup>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime must be constructable on startup");

    rt.block_on(async move {
        let actor_system = ActorSystem::new();
        let near_node =
            match nearcore::start_with_config(home_dir, near_config, actor_system.clone()).await {
                Ok(node) => node,
                Err(err) => {
                    let _ = ready_sender.send(Err(ChainGatewayError::StartupFailed {
                        msg: err.to_string(),
                    }));
                    return;
                }
            };

        let indexer_and_params = streamer_setup.map(|s| {
            let indexer =
                near_indexer::Indexer::from_near_node(s.indexer_config, s.near_config, &near_node);
            (indexer, s.subscriber)
        });

        let view_client = NearViewClientActorHandle::new(near_node.view_client);
        let client = NearClientActorHandle::new(near_node.client);
        let rpc_handler = NearRpcActorHandle::new(near_node.rpc_handler);

        let stream = if let Some((indexer, streamer_config)) = indexer_and_params {
            // Don't start the streamer until synced, or its `LatestSynced`
            // cursor pins at genesis. Raced against shutdown to stay responsive.
            tracing::info!(
                "chain-gateway waiting for node to finish syncing before streaming blocks."
            );
            let synced = await_sync_or_shutdown(client.wait_for_full_sync(), async {
                let _ = (&mut shutdown_receiver).await;
            })
            .await;
            if !synced {
                tracing::info!("shutdown requested before sync completed; exiting startup.");
                let _ = ready_sender.send(Err(ChainGatewayError::StartupFailed {
                    msg: "shutdown requested before node finished syncing".to_string(),
                }));
                actor_system.stop();
                return;
            }

            let raw_stream: Receiver<StreamerMessage> = indexer.streamer();
            match event_subscriber::streamer::start(
                streamer_config,
                raw_stream,
                view_client.clone(),
            )
            .await
            {
                Ok(rx) => Some(rx),
                Err(err) => {
                    let _ = ready_sender.send(Err(err));
                    return;
                }
            }
        } else {
            None
        };

        let _ = ready_sender.send(Ok((
            ChainGateway {
                view_client,
                client,
                rpc_handler,
            },
            stream,
        )));

        match shutdown_receiver.await {
            Ok(()) => {
                tracing::info!("node gracefully shutting down actor system");
            }
            _ => {
                tracing::info!("shutdown sender was dropped, shutting down actor system");
            }
        }

        actor_system.stop();
    });
}

/// Parameters for optionally starting the block-event streaming pipeline
/// alongside the nearcore node.
struct StreamerSetup {
    subscriber: BlockEventSubscriptions,
    indexer_config: near_indexer::IndexerConfig,
    near_config: NearConfig,
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
