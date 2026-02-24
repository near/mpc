use std::sync::Arc;

use crate::near_internals_wrapper::errors::RpcClientError;

#[derive(Clone)]
pub(crate) struct RpcHandlerWrapper {
    rpc_handler: near_async::multithread::MultithreadRuntimeHandle<near_client::RpcHandler>,
}

impl RpcHandlerWrapper {
    /// wraps the near-internal handle
    pub(crate) fn new(
        rpc_handler: near_async::multithread::MultithreadRuntimeHandle<near_client::RpcHandler>,
    ) -> Self {
        Self { rpc_handler }
    }

    /// Creates, signs, and submits a function call with the given method and serialized arguments.
    pub(crate) async fn submit_tx(
        &self,
        transaction: near_indexer::near_primitives::transaction::SignedTransaction,
    ) -> Result<(), RpcClientError> {
        let response = near_async::messaging::CanSendAsync::send_async(
            &self.rpc_handler,
            near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            },
        )
        .await
        .map_err(|e| RpcClientError::SubmitTransaction {
            source: Arc::new(e),
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
