use thiserror::Error;

pub type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum IndexerViewClientError {
    #[error("failed to query for final block")]
    FinalBlockQuery {
        #[source]
        source: DynError,
    },

    #[error("view client response error: {query}")]
    InvalidResponse {
        query: String,
        #[source]
        source: DynError,
    },
}

#[derive(Debug, Error)]
pub enum RpcClientError {
    #[error("failed to submit transaction to rpc client")]
    SubmitTransaction {
        #[source]
        source: DynError,
    },

    #[error("unexpected process transaction response: {response}")]
    UnexpectedProcessTransactionResponse {
        response: String,
    },
}
