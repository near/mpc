use std::fmt;

use near_account_id::AccountId;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NearClientError {
    #[error("near client failed to send async: {message}")]
    AsyncSendError { message: String },
    #[error("near client response error: {message}")]
    ResponseError { message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NearRpcError {
    #[error("failed to submit transaction: {message}")]
    SubmitTransaction { message: String },
    #[error("received invalid response: {response}")]
    ResponseError { response: String },
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NearViewClientError {
    #[error("near view client failed to send async for {query}: {message}")]
    AsyncSendError {
        query: NearViewClientQuery,
        message: String,
    },
    #[error("near view client response error for {query}: {message}")]
    ResponseError {
        query: NearViewClientQuery,
        message: String,
    },
    #[error("near view client unexpected response for {query}: {message}")]
    UnexpectedResponseError {
        query: NearViewClientQuery,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NearViewClientQuery {
    LatestFinalBlock,
    ViewMethod {
        contract_id: AccountId,
        method_name: String,
    },
}

impl fmt::Display for NearViewClientQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatestFinalBlock => write!(f, "query latest final block"),
            Self::ViewMethod {
                contract_id,
                method_name,
            } => write!(f, "view {contract_id}.{method_name}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainGatewayOp {
    SubmitFunctionCallTransaction {
        signer: String,
        receiver_id: String,
        method_name: String,
    },
    ViewQuery {
        account_id: String,
        method_name: String,
    },
}

impl std::fmt::Display for ChainGatewayOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainGatewayOp::SubmitFunctionCallTransaction {
                signer,
                receiver_id,
                method_name,
            } => {
                write!(
                    f,
                    "submitting function call {}.{} signed by {}",
                    receiver_id, method_name, signer
                )
            }
            ChainGatewayOp::ViewQuery {
                account_id,
                method_name,
            } => {
                write!(f, "calling view function {}.{}", account_id, method_name)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainGatewayError {
    #[error("deserialization error: {message}")]
    Deserialization { message: String },

    #[error("failure loading config with {msg}")]
    FailureLoadingConfig { msg: String },

    #[error("failed to fetch latest final block while {op}: {message}")]
    FetchFinalBlock { op: ChainGatewayOp, message: String },

    #[error("monitoring task closed")]
    MonitoringClosed,

    #[error("starting neard node failed with {msg}")]
    StartupFailed { msg: String },

    #[error("serialization error while {op}: {message}")]
    Serialization { op: ChainGatewayOp, message: String },

    #[error("failed to submit signed transaction while {op}: {message}")]
    SubmitSignedTransaction { op: ChainGatewayOp, message: String },

    #[error("view client error while {op}: {message}")]
    ViewError { op: ChainGatewayOp, message: String },
}
