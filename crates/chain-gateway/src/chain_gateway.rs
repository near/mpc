use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{
    ClientWrapper, RpcHandlerWrapper, ViewClientWrapper, ViewFunctionCall,
};
use crate::stats::IndexerStats;

#[derive(Clone)]
pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: ViewClientWrapper,
    /// For querying blockchain sync status.
    client: ClientWrapper,
    /// For sending txs to the chain.
    rpc_handler: RpcHandlerWrapper,
    /// Stores runtime indexing statistics.
    _stats: Arc<Mutex<IndexerStats>>,
}

#[allow(async_fn_in_trait)]
pub trait LatestFinalBlock {
    type Error;
    async fn latest_final_block(
        &self,
    ) -> Result<near_indexer_primitives::views::BlockView, Self::Error>;
}

impl LatestFinalBlock for ChainGateway {
    type Error = ChainGatewayError;
    async fn latest_final_block(
        &self,
    ) -> Result<near_indexer_primitives::views::BlockView, Self::Error> {
        self.view_client
            .latest_final_block()
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                op: ChainGatewayOp::FetchFinalBlock,
                source: Box::new(err),
            })
    }
}

/// waits for full sync and then queries account_id with method_name and args.
#[allow(async_fn_in_trait)]
pub trait FinalizedStateView {
    type Error;
    async fn view_call(
        &self,
        account_id: &near_account_id::AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), Self::Error>;
}

impl FinalizedStateView for ChainGateway {
    type Error = ChainGatewayError;
    async fn view_call(
        &self,
        account_id: &near_account_id::AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), Self::Error> {
        self.wait_for_full_sync().await;
        self.view_client
            .view_function_query(&ViewFunctionCall {
                account_id: account_id.clone(),
                method_name: method_name.to_string(),
                args,
            })
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                // note: not sure we need to log account_id and method name here. It can be read in the boxed error
                op: ChainGatewayOp::ViewCall {
                    account_id: account_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Box::new(err),
            })
    }
}

impl ChainGateway {
    // todo: remove this method soon. Stats should be internal to this crate
    pub fn stats(&self) -> Arc<Mutex<IndexerStats>> {
        self._stats.clone()
    }

    pub async fn wait_for_full_sync(&self) {
        const INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        loop {
            tokio::time::sleep(INTERVAL).await;
            match self.client.is_syncing().await {
                Ok(is_syncing) => {
                    if !is_syncing {
                        return;
                    }
                    tracing::info!("wating for full sync");
                }
                Err(err) => {
                    tracing::warn!(err = %err, "error while waiting for sync");
                }
            }
        }
    }

    pub async fn submit_tx(
        &self,
        transaction: near_indexer::near_primitives::transaction::SignedTransaction,
    ) -> Result<(), ChainGatewayError> {
        self.rpc_handler
            .submit_tx(transaction)
            .await
            .map_err(|err| ChainGatewayError::RpcClient {
                source: Box::new(err),
            })
    }

    ///// waits for full sync and then queries account_id with method_name and args.
    //pub async fn function_query(
    //    &self,
    //    account_id: &near_account_id::AccountId,
    //    method_name: &str,
    //    args: Vec<u8>,
    //) -> Result<(u64, Vec<u8>), ChainGatewayError> {
    //    self.wait_for_full_sync().await;
    //    self.view_client
    //        .view_function_query(&ViewFunctionCall {
    //            account_id: account_id.clone(),
    //            method_name: method_name.to_string(),
    //            args,
    //        })
    //        .await
    //        .map_err(|err| ChainGatewayError::ViewClient {
    //            // note: not sure we need to log account_id and method name here. It can be read in                // the boxed error
    //            // todo: no crate::errors
    //            op: ChainGatewayOp::ViewCall {
    //                account_id: account_id.to_string(),
    //                method_name: method_name.to_string(),
    //            },
    //            source: Box::new(err),
    //        })
    //}
}

pub async fn start_with_streamer(
    config: near_indexer::IndexerConfig,
) -> Result<(ChainGateway, mpsc::Receiver<near_indexer::StreamerMessage>), ChainGatewayError> {
    let near_config =
        config
            .load_near_config()
            .map_err(|err| ChainGatewayError::FailureLoadingConfig {
                msg: err.to_string(),
            })?;

    let near_node = near_indexer::Indexer::start_near_node(&config, near_config.clone())
        .await
        .map_err(|err| ChainGatewayError::StartupFailed {
            msg: err.to_string(),
        })?;

    let indexer = near_indexer::Indexer::from_near_node(config, near_config, &near_node);

    let stream = indexer.streamer();

    let view_client = ViewClientWrapper::new(near_node.view_client);
    let client = ClientWrapper::new(near_node.client);
    let rpc_handler = RpcHandlerWrapper::new(near_node.rpc_handler);
    let stats = Arc::new(Mutex::new(IndexerStats::new()));
    tokio::spawn(indexer_logger(stats.clone(), view_client.clone()));

    Ok((
        ChainGateway {
            view_client,
            client,
            rpc_handler,
            _stats: stats,
        },
        stream,
    ))
}

pub(crate) async fn indexer_logger(
    stats: Arc<Mutex<IndexerStats>>,
    view_client: ViewClientWrapper,
) {
    let interval_secs = 10;
    let mut prev_blocks_processed_count: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        let stats_lock = stats.lock().await;
        let stats_copy = stats_lock.clone();
        drop(stats_lock);

        let block_processing_speed: f64 = ((stats_copy.blocks_processed_count
            - prev_blocks_processed_count) as f64)
            / (interval_secs as f64);

        let time_to_catch_the_tip_duration = if block_processing_speed > 0.0 {
            if let Ok(block_height) = view_client
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
            target: "chain gateway",
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
