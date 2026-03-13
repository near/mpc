use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use crate::errors::{ChainGatewayError, NearClientError, NearRpcError, NearViewClientError};
use crate::near_internals_wrapper::{
    NearClientActorHandle, NearRpcActorHandle, NearViewClientActorHandle,
};
use crate::primitives::{
    FetchLatestFinalBlockInfo, IsSyncing, QueryViewFunction, SubmitSignedTransaction,
};
use crate::stats::{IndexerStats, indexer_logger};
use crate::types::ObservedState;

#[derive(Clone)]
pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: NearViewClientActorHandle,
    /// For querying blockchain sync status.
    client: NearClientActorHandle,
    /// For sending txs to the chain.
    rpc_handler: NearRpcActorHandle,
    // todo: remove stats
    /// Stores runtime indexing statistics.
    _stats: Arc<Mutex<IndexerStats>>,
}

impl IsSyncing for ChainGateway {
    type Error = NearClientError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.client.is_syncing().await
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

impl ChainGateway {
    pub async fn start(
        config: near_indexer::IndexerConfig,
    ) -> Result<ChainGateway, ChainGatewayError> {
        let near_config =
            config
                .load_near_config()
                .map_err(|err| ChainGatewayError::FailureLoadingConfig {
                    msg: err.to_string(),
                })?;

        let near_node = near_indexer::Indexer::start_near_node(&config, near_config)
            .await
            .map_err(|err| ChainGatewayError::StartupFailed {
                msg: err.to_string(),
            })?;

        let view_client = NearViewClientActorHandle::new(near_node.view_client);
        let client = NearClientActorHandle::new(near_node.client);

        let rpc_handler = NearRpcActorHandle::new(near_node.rpc_handler);
        // todo: remove states
        let stats = Arc::new(Mutex::new(IndexerStats::new()));
        tokio::spawn(indexer_logger(stats.clone(), view_client.clone()));

        Ok(ChainGateway {
            view_client,
            client,
            rpc_handler,
            _stats: stats,
        })
    }
    pub async fn start_with_streamer(
        config: near_indexer::IndexerConfig,
    ) -> Result<(ChainGateway, mpsc::Receiver<near_indexer::StreamerMessage>), ChainGatewayError>
    {
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
        let view_client = NearViewClientActorHandle::new(near_node.view_client);
        let client = NearClientActorHandle::new(near_node.client);

        let rpc_handler = NearRpcActorHandle::new(near_node.rpc_handler);
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

impl ChainGateway {
    // todo: remove this method soon. Stats should be internal to this crate
    pub fn stats(&self) -> Arc<Mutex<IndexerStats>> {
        self._stats.clone()
    }
}
