use near_account_id::AccountId;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::contract_state::ContractStateViewer;
use crate::errors::ChainGatewayError;
use crate::logger::indexer_logger;
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
