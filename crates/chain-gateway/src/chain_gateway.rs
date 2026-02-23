use near_account_id::AccountId;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::contract_state::ContractStateViewer;
use crate::errors::ChainGatewayError;
use crate::near_internals_wrapper::{ClientWrapper, RpcHandlerWrapper, ViewClientWrapper};
use crate::stats::IndexerStats;
use crate::transaction_sender::TransactionSender;

#[derive(Clone)]
pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: Arc<ViewClientWrapper>,
    /// For querying blockchain sync status.
    client: Arc<ClientWrapper>,
    /// For sending txs to the chain.
    rpc_handler: Arc<RpcHandlerWrapper>,
    /// Stores runtime indexing statistics.
    _stats: Arc<Mutex<IndexerStats>>,
}

impl ChainGateway {
    pub fn contract_state_viewer(&self, contract_id: AccountId) -> ContractStateViewer {
        ContractStateViewer {
            client: self.client.clone(),
            view_client: self.view_client.clone(),
            contract_id,
        }
    }
    pub fn transaction_sender(&self) -> TransactionSender {
        TransactionSender::new(self.rpc_handler.clone(), self.view_client.clone())
    }
}

impl ChainGateway {
    // todo: remove this method soon. Stats should be internal to this crate
    pub fn stats(&self) -> Arc<Mutex<IndexerStats>> {
        self._stats.clone()
    }
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

    let view_client = Arc::new(ViewClientWrapper::new(near_node.view_client));
    let client = Arc::new(ClientWrapper::new(near_node.client));
    let rpc_handler = Arc::new(RpcHandlerWrapper::new(near_node.rpc_handler));
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
    view_client: Arc<ViewClientWrapper>,
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
