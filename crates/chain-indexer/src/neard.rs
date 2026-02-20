use near_async::{multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle};
use near_client::{RpcHandler, ViewClientActorInner, client_actor::ClientActorInner};
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer::{Indexer, IndexerConfig, StreamerMessage};
use near_indexer_primitives::views::BlockView;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::near_internals::client::IndexerClient;
use crate::near_internals::errors::{IndexerViewClientError, RpcClientError};
use crate::near_internals::rpc::IndexerRpcHandler;
use crate::near_internals::view_client::IndexerViewClient;
use crate::stats::IndexerStats;

pub struct ChainIndexer {
    /// For querying blockchain state.
    view_client: IndexerViewClient,
    /// For querying blockchain sync status.
    client: IndexerClient,
    /// For sending txs to the chain.
    rpc_handler: IndexerRpcHandler,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl ChainIndexer {
    pub fn new(
        view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
        client: TokioRuntimeHandle<ClientActorInner>,
        rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
    ) -> Self {
        Self {
            view_client: IndexerViewClient { view_client },
            client: IndexerClient { client },
            rpc_handler: IndexerRpcHandler { rpc_handler },
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }

    pub async fn latest_final_block(&self) -> Result<BlockView, IndexerViewClientError> {
        self.view_client.latest_final_block().await
    }

    pub async fn submit_tx(&self, transaction: SignedTransaction) -> Result<(), RpcClientError> {
        self.rpc_handler.submit_tx(transaction).await
    }
    pub async fn send_async_view_client_query(
        &self,
        query: near_client::Query,
    ) -> Result<(), IndexerViewClientError> {
        self.view_client.send_async_query(query).await
    }
    // // todo: remove this when view client is done
    // pub fn view_client(&self) -> &IndexerViewClient {
    //     &self.view_client
    // }
}

pub async fn start_with_streamer(
    config: IndexerConfig,
) -> (ChainIndexer, mpsc::Receiver<StreamerMessage>) {
    let near_config = config.load_near_config().expect("near config is present");

    let near_node = Indexer::start_near_node(&config, near_config.clone())
        .await
        .expect("near node has started");

    let indexer = Indexer::from_near_node(config, near_config, &near_node);

    let stream = indexer.streamer();

    (
        ChainIndexer::new(
            near_node.view_client,
            near_node.client,
            near_node.rpc_handler,
        ),
        stream,
    )
}

pub async fn run(config: IndexerConfig) -> ChainIndexer {
    let near_config = config.load_near_config().expect("near config is present");

    let near_node = Indexer::start_near_node(&config, near_config.clone())
        .await
        .expect("near node has started");

    ChainIndexer::new(
        near_node.view_client,
        near_node.client,
        near_node.rpc_handler,
    )
}

pub(crate) async fn indexer_logger(indexer_state: Arc<ChainIndexer>) {
    let interval_secs = 10;
    let mut prev_blocks_processed_count: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        let stats_lock = indexer_state.stats.lock().await;
        let stats_copy = stats_lock.clone();
        drop(stats_lock);

        let block_processing_speed: f64 = ((stats_copy.blocks_processed_count
            - prev_blocks_processed_count) as f64)
            / (interval_secs as f64);

        let time_to_catch_the_tip_duration = if block_processing_speed > 0.0 {
            if let Ok(block_height) = indexer_state
                .view_client
                .latest_final_block()
                .await
                .map(|block| block.header.height)
            {
                let blocks_behind = if block_height > stats_copy.last_processed_block_height {
                    block_height - stats_copy.last_processed_block_height
                } else {
                    0 // We're ahead of the chain tip, no catching up needed
                };

                Some(std::time::Duration::from_millis(
                    ((blocks_behind as f64 / block_processing_speed) * 1000f64) as u64,
                ))
            } else {
                None
            }
        } else {
            None
        };

        tracing::info!(
            target: "indexer",
            "# {} | Blocks processing: {}| Blocks done: {}. Bps {:.2} b/s {}",
            stats_copy.last_processed_block_height,
            stats_copy.block_heights_processing.len(),
            stats_copy.blocks_processed_count,
            block_processing_speed,
            if let Some(duration) = time_to_catch_the_tip_duration.filter(|d| d.as_secs() > 0) {
                format!(
                    " | {} to catch up the tip",
                    humantime::format_duration(duration)
                )
            } else {
                "".to_string()
            }
        );
        prev_blocks_processed_count = stats_copy.blocks_processed_count;
    }
}
