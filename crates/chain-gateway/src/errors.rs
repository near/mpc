use std::sync::Arc;

use thiserror::Error;

pub type SharedError = Arc<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub enum ChainGatewayOp {
    FetchFinalBlock,
    ViewCall {
        account_id: String,
        method_name: String,
    },
}

impl std::fmt::Display for ChainGatewayOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainGatewayOp::FetchFinalBlock => write!(f, "fetching final block"),
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

    #[error("failure loading config with {msg}")]
    FailureLoadingConfig {
        // work-around seems like nearcore is building anyhow without `std`
        msg: String,
    },

    #[error("starting neard node failed with {msg}")]
    StartupFailed {
        // work-around seems like nearcore is building anyhow without `std`
        msg: String,
    },

    #[error("send transaction failed")]
    SendTransactionError {
        context: String,
        #[source]
        source: SharedError,
    },
}
