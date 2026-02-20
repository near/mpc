pub(crate) mod errors;
pub(crate) mod types;

use errors::{GetBlockError, QueryError, ViewClientError};
use near_async::{messaging::CanSendAsync, multithread::MultithreadRuntimeHandle};
use near_client::ViewClientActorInner;
use near_indexer_primitives::{
    types::{BlockReference, Finality},
    views::{BlockView, QueryRequest, QueryResponseKind},
};
use std::fmt;
use types::ViewFunctionCall;

#[derive(Clone)]
pub(crate) struct IndexerViewClient {
    view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
}

impl IndexerViewClient {
    pub(crate) fn new(view_client: MultithreadRuntimeHandle<ViewClientActorInner>) -> Self {
        Self { view_client }
    }
    pub(crate) async fn latest_final_block(&self) -> Result<BlockView, ViewClientError> {
        let block_query = near_client::GetBlock(BlockReference::Finality(Finality::Final));
        let send_result = self.view_client.send_async(block_query).await;
        let response_result = send_result.map_err(|err| GetBlockError::Send {
            source: Box::new(err),
        })?;
        let response = response_result.map_err(|err| GetBlockError::Response {
            source: Box::new(err),
        })?;
        Ok(response)
    }

    pub(crate) async fn view_function_query(
        &self,
        request: &ViewFunctionCall,
    ) -> Result<(u64, Vec<u8>), ViewClientError> {
        let query = near_client::Query {
            block_reference: BlockReference::Finality(Finality::Final),
            request: request.into(),
        };
        let send_result = self.view_client.send_async(query).await;
        let response_result = send_result.map_err(|err| QueryError::Send {
            op: request.clone(),
            source: Box::new(err),
        })?;
        let response = response_result.map_err(|err| QueryError::Response {
            op: request.clone(),
            source: Box::new(err),
        })?;
        match response.kind {
            QueryResponseKind::CallResult(call_result) => {
                Ok((response.block_height, call_result.result))
            }
            other => Err(QueryError::UnexpectedResponse {
                view_call: request.clone(),
                response: other,
            }
            .into()),
        }
    }
}

impl fmt::Display for ViewFunctionCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "view function call {}.{} (args_len={})",
            self.account_id,
            self.method_name,
            self.args.len()
        )
    }
}

impl From<&ViewFunctionCall> for QueryRequest {
    fn from(value: &ViewFunctionCall) -> Self {
        QueryRequest::CallFunction {
            account_id: value.account_id.clone(),
            method_name: value.method_name.to_string(),
            args: value.args.clone().into(),
        }
    }
}
