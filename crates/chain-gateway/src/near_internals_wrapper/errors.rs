use thiserror::Error;

pub type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub(crate) enum RpcClientError {
    #[error("failed to submit transaction to rpc client")]
    SubmitTransaction {
        #[source]
        source: DynError,
    },

    #[error("unexpected process transaction response: {response}")]
    UnexpectedProcessTransactionResponse { response: String },
}

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    #[error("failed to send async")]
    AsyncSendError {
        #[source]
        source: DynError,
    },
    #[error("received error response")]
    ResponseError {
        #[source]
        source: DynError,
    },
}
