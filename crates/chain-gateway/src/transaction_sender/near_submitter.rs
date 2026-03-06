use async_trait::async_trait;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::near_primitives::transaction::SignedTransaction;
use std::sync::Arc;

use crate::errors::ChainGatewayError;
use crate::near_internals_wrapper::{RpcHandlerWrapper, ViewClientWrapper};

use super::traits::TransactionSubmitter;

#[derive(Clone)]
pub struct NearTransactionSubmitter {
    rpc_handler: Arc<RpcHandlerWrapper>,
    view_client: Arc<ViewClientWrapper>,
}

impl NearTransactionSubmitter {
    pub(crate) fn new(
        rpc_handler: Arc<RpcHandlerWrapper>,
        view_client: Arc<ViewClientWrapper>,
    ) -> Self {
        Self {
            rpc_handler,
            view_client,
        }
    }
}

#[async_trait]
impl TransactionSubmitter for NearTransactionSubmitter {
    async fn latest_final_block_info(&self) -> Result<(CryptoHash, u64), ChainGatewayError> {
        let block = self.view_client.latest_final_block().await.map_err(|err| {
            ChainGatewayError::SendTransactionError {
                context: "could not query last final block".to_string(),
                source: Arc::new(err),
            }
        })?;
        Ok((block.header.hash, block.header.height))
    }

    async fn submit_signed_tx(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), ChainGatewayError> {
        self.rpc_handler
            .submit_tx(transaction)
            .await
            .map_err(|err| ChainGatewayError::RpcClient {
                source: Arc::new(err),
            })
    }
}
