use thiserror::Error;

use crate::near_internals_wrapper::view_client::request::ViewFunctionCall;

pub type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

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
        source: DynError,
    },
    #[error("get final block: response error")]
    Response {
        #[source]
        source: DynError,
    },
}

#[derive(Debug, Error)]
pub(crate) enum QueryError {
    #[error("query view call {op}: send error")]
    Send {
        op: ViewFunctionCall,
        #[source]
        source: DynError,
    },
    #[error("query view call {op}: response error")]
    Response {
        op: ViewFunctionCall,
        #[source]
        source: DynError,
    },
    #[error("unexpected response: {response:?} for view_call: {view_call}")]
    UnexpectedResponse {
        view_call: ViewFunctionCall,
        // we don't want to leak nearcore internal types
        response: String,
    },
}
