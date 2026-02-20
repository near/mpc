use std::{fmt, sync::Arc};

use near_account_id::AccountId;
use thiserror::Error;

pub type SharedError = Arc<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum NearRpcClientError {
    #[error("failed to submit transaction to rpc client")]
    SubmitTransaction {
        #[source]
        source: SharedError,
    },

    #[error("unexpected process transaction response: {response}")]
    UnexpectedProcessTransactionResponse { response: String },
}

#[derive(Debug, Error)]
pub enum NearClientError {
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
pub struct NearViewClientError {
    pub query: ViewClientQuery,
    pub kind: NearViewClientErrorKind,
    #[source]
    pub source: SharedError,
}

#[derive(Debug)]
pub enum ViewClientQuery {
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
pub enum NearViewClientErrorKind {
    SendError,
    ResponseError,
    UnexpectedResponse,
}

impl fmt::Display for NearViewClientErrorKind {
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
pub struct UnexpectedResponseError(pub String);

#[derive(Debug, Clone)]
pub enum ChainGatewayOp {
    ViewCall {
        account_id: String,
        method_name: String,
    },
}

impl std::fmt::Display for ChainGatewayOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainGatewayOp::ViewCall {
                account_id,
                method_name,
            } => {
                write!(f, "calling view function {}.{}", account_id, method_name)
            }
        }
    }
}

#[derive(Clone, Debug, Error)]
pub enum ChainGatewayError {
    #[error("monitoring task closed")]
    MonitoringClosed,

    #[error("view client error while {op}")]
    ViewClient {
        op: ChainGatewayOp,
        #[source]
        source: SharedError,
    },

    #[error("serialization error {op}")]
    Serialization {
        op: ChainGatewayOp,
        #[source]
        source: SharedError,
    },

    #[error("deserialization error")]
    Deserialization {
        #[source]
        source: SharedError,
    },

    #[error("rpc client error")]
    RpcClient {
        #[source]
        source: SharedError,
    },

    #[error("failed to fetch latest final block")]
    FetchFinalBlock {
        #[source]
        source: SharedError,
    },

    #[error("failed to submit signed transaction")]
    SubmitTransaction {
        #[source]
        source: SharedError,
    },

    #[error("failure loading config with {msg}")]
    FailureLoadingConfig { msg: String },

    #[error("starting neard node failed with {msg}")]
    StartupFailed { msg: String },
}
