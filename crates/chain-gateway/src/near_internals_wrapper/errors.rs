use std::{fmt, sync::Arc};

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
#[error("query view {kind} error for {query}")]
pub(crate) struct ViewClientError {
    pub(crate) query: ViewClientQuery,
    pub(crate) kind: ViewClientErrorKind,
    #[source]
    pub(crate) source: SharedError,
}

#[derive(Debug)]
pub(crate) enum ViewClientQuery {
    LatestFinalBlock,
    ViewMethod {
        contract_id: AccountId,
        method_name: String,
    },
}
impl fmt::Display for ViewClientQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatestFinalBlock => write!(f, "latest final block query"),
            Self::ViewMethod {
                contract_id,
                method_name,
            } => write!(f, "view {contract_id}.{method_name}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ViewClientErrorKind {
    SendError,
    ResponseError,
    UnexpectedResponse,
}

impl fmt::Display for ViewClientErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendError => write!(f, "send error"),
            Self::ResponseError => write!(f, "response error"),
            Self::UnexpectedResponse => write!(f, "unexpected response"),
        }
    }
}

#[derive(Debug, Error)]
#[error("unexpected response: {0}")]
pub(crate) struct UnexpectedResponseError(pub String);
