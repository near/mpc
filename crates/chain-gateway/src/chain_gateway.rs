use near_account_id::AccountId;
use near_async::ActorSystem;
use near_indexer::near_primitives::transaction::SignedTransaction;

use crate::errors::{ChainGatewayError, NearClientError, NearRpcError, NearViewClientError};
use crate::near_internals_wrapper::{
    NearClientActorHandle, NearRpcActorHandle, NearViewClientActorHandle,
};
use crate::primitives::{
    FetchLatestFinalBlockInfo, IsSyncing, QueryViewFunction, SubmitSignedTransaction,
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
    /// Handle to the actor system that owns the nearcore actors.
    actor_system: ActorSystem,
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
    pub async fn start(
        config: near_indexer::IndexerConfig,
    ) -> Result<ChainGateway, ChainGatewayError> {
        let near_config =
            config
                .load_near_config()
                .map_err(|err| ChainGatewayError::FailureLoadingConfig {
                    msg: err.to_string(),
                })?;

        let actor_system = ActorSystem::new();
        let near_node =
            nearcore::start_with_config(&config.home_dir, near_config, actor_system.clone())
                .await
                .map_err(|err| ChainGatewayError::StartupFailed {
                    msg: err.to_string(),
                })?;

        let view_client = NearViewClientActorHandle::new(near_node.view_client);
        let client = NearClientActorHandle::new(near_node.client);
        let rpc_handler = NearRpcActorHandle::new(near_node.rpc_handler);

        Ok(ChainGateway {
            view_client,
            client,
            rpc_handler,
            actor_system,
        })
    }

    /// Signals all nearcore actors owned by this gateway to stop.
    ///
    /// After calling this, use [`near_store::db::RocksDB::block_until_all_instances_are_dropped`]
    /// to wait for RocksDB cleanup before dropping the tokio runtime.
    pub fn shutdown(&self) {
        self.actor_system.stop();
    }
}
