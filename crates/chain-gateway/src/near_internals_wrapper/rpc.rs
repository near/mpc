use std::sync::Arc;

use crate::{errors::NearRpcError, primitives::SubmitSignedTransaction};

/// Arc-Wrapper around near-internal handler struct
#[derive(Clone)]
pub(crate) struct NearRpcActorHandle {
    rpc_handler: Arc<near_async::multithread::MultithreadRuntimeHandle<near_client::RpcHandler>>,
}

impl NearRpcActorHandle {
    pub(crate) fn new(
        rpc_handler: near_async::multithread::MultithreadRuntimeHandle<near_client::RpcHandler>,
    ) -> Self {
        Self {
            rpc_handler: Arc::new(rpc_handler),
        }
    }
}

impl SubmitSignedTransaction for NearRpcActorHandle {
    type Error = NearRpcError;
    /// Submits a signed transaction to the chain.
    async fn submit_signed_transaction(
        &self,
        transaction: near_indexer::near_primitives::transaction::SignedTransaction,
    ) -> Result<(), Self::Error> {
        let response = near_async::messaging::CanSendAsync::send_async(
            self.rpc_handler.as_ref(),
            near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            },
        )
        .await
        .map_err(|err| NearRpcError::SubmitTransaction {
            message: err.to_string(),
        })?;

        match response {
            // We're not a validator, so we should always be routing the transaction.
            near_client::ProcessTxResponse::RequestRouted => Ok(()),
            _ => Err(NearRpcError::ResponseError {
                response: format!("{:?}", response),
            }),
        }
    }
}
