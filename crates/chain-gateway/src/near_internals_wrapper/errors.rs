use std::sync::Arc;

use near_account_id::AccountId;
use thiserror::Error;

pub type SharedError = Arc<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub(crate) enum RpcClientError {
    #[error("failed to submit transaction to rpc client")]
    SubmitTransaction {
        #[source]
        source: SharedError,
    },

    #[error("unexpected process transaction response: {response}")]
    UnexpectedProcessTransactionResponse { response: String },
}

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    #[error("failed to send async")]
    AsyncSendError {
        #[source]
        source: SharedError,
    },
    #[error("received error response")]
    ResponseError {
        #[source]
        source: SharedError,
    },
}

#[derive(Debug, Error)]
pub(crate) enum ViewClientError {
    #[error(transparent)]
    GetBlock(#[from] GetBlockError),

    #[error(transparent)]
    Query(#[from] QueryError),
}

#[derive(Debug, Error)]
pub(crate) enum GetBlockError {
    #[error("get final block: send error")]
    Send {
        #[source]
        source: SharedError,
    },
    #[error("get final block: response error")]
    Response {
        #[source]
        source: SharedError,
    },
}

#[derive(Debug, Error)]
#[error(
    "query view call on contract {contract_id} with method {method_name} and arguments: {args:?}: {kind}"
)]
pub(crate) struct QueryError {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,

    #[source]
    pub kind: QueryErrorKind,
}
#[derive(Debug, Error)]
pub(crate) enum QueryErrorKind {
    #[error("send error")]
    Send {
        #[source]
        source: SharedError,
    },

    #[error("response error")]
    Response {
        #[source]
        source: SharedError,
    },

    #[error("unexpected response: {response:?}")]
    UnexpectedResponse {
        // avoid leaking nearcore types
        response: String,
    },
}
