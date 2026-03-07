use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::errors::ChainGatewayError;
use crate::near_internals_wrapper::client::ClientWrapper;
use crate::near_internals_wrapper::rpc::RpcHandlerWrapper;
use crate::near_internals_wrapper::view_client::ViewClientWrapper;
use crate::state_viewer::NearContractViewer;
use crate::stats::{IndexerStats, indexer_logger};
use crate::transaction_sender::NearTransactionSubmitter;

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

impl ChainGateway {
    pub fn viewer(&self) -> NearContractViewer {
        NearContractViewer::new(self.client.clone(), self.view_client.clone())
    }

    pub fn transaction_sender(&self) -> NearTransactionSubmitter {
        NearTransactionSubmitter::new(self.rpc_handler.clone(), self.view_client.clone())
    }
}

impl ChainGateway {
    // todo: remove this method soon. Stats should be internal to this crate
    pub fn stats(&self) -> Arc<Mutex<IndexerStats>> {
        self._stats.clone()
    }
}

// todo: to start a specific block, need to change indexer config!
// sync_mode::Block(start_at_block_height)
// we need to log this somewhere (write to disk) such that it can get picked up if interrupted
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
