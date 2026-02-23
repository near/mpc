use thiserror::Error;

pub type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

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

#[derive(Debug, Error)]
pub enum ChainGatewayError {
    #[error("view client error while {op}")]
    ViewClient {
        op: ChainGatewayOp,
        #[source]
        source: DynError,
    },

    #[error("rpc client error")]
    RpcClient {
        #[source]
        source: DynError,
    },

    #[error("failure loading config")]
    FailureLoadingConfig {
        // work-around seems like nearcore is building anyhow without `std`
        msg: String,
    },

    #[error("starting neard node failed")]
    StartupFailed { msg: String },
}
