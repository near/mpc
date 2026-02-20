use near_async::{messaging::CanSendAsync, multithread::MultithreadRuntimeHandle};
use near_client::RpcHandler;
use near_indexer::near_primitives::transaction::SignedTransaction;

use super::errors::RpcClientError;

pub(crate) struct IndexerRpcHandler {
    rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
}

impl IndexerRpcHandler {
    pub(crate) fn new(rpc_handler: MultithreadRuntimeHandle<RpcHandler>) -> Self {
        Self { rpc_handler }
    }
    /// Creates, signs, and submits a function call with the given method and serialized arguments.
    pub(crate) async fn submit_tx(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), RpcClientError> {
        let response = self
            .rpc_handler
            .send_async(near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            })
            .await
            .map_err(|e| RpcClientError::SubmitTransaction {
                source: Box::new(e),
            })?;

        match response {
            // We're not a validator, so we should always be routing the transaction.
            near_client::ProcessTxResponse::RequestRouted => Ok(()),
            _ => Err(RpcClientError::UnexpectedProcessTransactionResponse {
                response: format!("{:?}", response),
            }),
        }
    }
}
