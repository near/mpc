use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer::{Indexer, IndexerConfig, StreamerMessage};
use near_indexer_primitives::views::BlockView;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::errors::ChainGatewayError;
use crate::near_internals::client::IndexerClient;
use crate::near_internals::rpc::IndexerRpcHandler;
use crate::near_internals::view_client::IndexerViewClient;
use crate::near_internals::view_client::types::ViewFunctionCall;
use crate::stats::IndexerStats;

pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: IndexerViewClient,
    /// For querying blockchain sync status.
    client: IndexerClient,
    /// For sending txs to the chain.
    rpc_handler: IndexerRpcHandler,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl ChainGateway {
    // todo: remove this method soon. Stats should be internal to this crate
    pub fn stats(&self) -> Arc<Mutex<IndexerStats>> {
        self.stats.clone()
    }
    pub async fn wait_for_full_sync(&self) {
        self.client.wait_for_full_sync().await
    }

    pub async fn latest_final_block(&self) -> Result<BlockView, ChainGatewayError> {
        self.view_client
            .latest_final_block()
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                op: crate::errors::ChainGatewayOp::FetchFinalBlock,
                source: Box::new(err),
            })
    }

    pub async fn submit_tx(&self, transaction: SignedTransaction) -> Result<(), ChainGatewayError> {
        self.rpc_handler
            .submit_tx(transaction)
            .await
            .map_err(|err| ChainGatewayError::RpcClient {
                source: Box::new(err),
            })
    }

    pub async fn function_query(
        &self,
        account_id: &AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), ChainGatewayError> {
        self.view_client
            .view_function_query(&ViewFunctionCall {
                account_id: account_id.clone(),
                method_name: method_name.to_string(),
                args,
            })
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                // note: not sure we need to log account_id and method name here. It can be read in                // the boxed error
                op: crate::errors::ChainGatewayOp::ViewCall {
                    account_id: account_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Box::new(err),
            })
    }

    // // todo: remove this when view client is done
    // pub fn view_client(&self) -> &IndexerViewClient {
    //     &self.view_client
    // }
}

/// todo: return error
pub async fn start_with_streamer(
    config: IndexerConfig,
) -> (ChainGateway, mpsc::Receiver<StreamerMessage>) {
    let near_config = config.load_near_config().expect("near config is present");

    let near_node = Indexer::start_near_node(&config, near_config.clone())
        .await
        .expect("near node has started");

    let indexer = Indexer::from_near_node(config, near_config, &near_node);

    let stream = indexer.streamer();

    (
        ChainGateway {
            view_client: IndexerViewClient::new(near_node.view_client),
            client: IndexerClient::new(near_node.client),
            rpc_handler: IndexerRpcHandler::new(near_node.rpc_handler),
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        },
        stream,
    )
}

//pub(crate) async fn indexer_logger(indexer_state: Arc<ChainIndexer>) {
//    let interval_secs = 10;
//    let mut prev_blocks_processed_count: u64 = 0;
//
//    loop {
//        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
//        let stats_lock = indexer_state.stats.lock().await;
//        let stats_copy = stats_lock.clone();
//        drop(stats_lock);
//
//        let block_processing_speed: f64 = ((stats_copy.blocks_processed_count
//            - prev_blocks_processed_count) as f64)
//            / (interval_secs as f64);
//
//        let time_to_catch_the_tip_duration = if block_processing_speed > 0.0 {
//            if let Ok(block_height) = indexer_state
//                .view_client
//                .latest_final_block()
//                .await
//                .map(|block| block.header.height)
//            {
//                let blocks_behind = if block_height > stats_copy.last_processed_block_height {
//                    block_height - stats_copy.last_processed_block_height
//                } else {
//                    0 // We're ahead of the chain tip, no catching up needed
//                };
//
//                Some(std::time::Duration::from_millis(
//                    ((blocks_behind as f64 / block_processing_speed) * 1000f64) as u64,
//                ))
//            } else {
//                None
//            }
//        } else {
//            None
//        };
//
//        tracing::info!(
//            target: "indexer",
//            "# {} | Blocks processing: {}| Blocks done: {}. Bps {:.2} b/s {}",
//            stats_copy.last_processed_block_height,
//            stats_copy.block_heights_processing.len(),
//            stats_copy.blocks_processed_count,
//            block_processing_speed,
//            if let Some(duration) = time_to_catch_the_tip_duration.filter(|d| d.as_secs() > 0) {
//                format!(
//                    " | {} to catch up the tip",
//                    humantime::format_duration(duration)
//                )
//            } else {
//                "".to_string()
//            }
//        );
//        prev_blocks_processed_count = stats_copy.blocks_processed_count;
//    }
//}
