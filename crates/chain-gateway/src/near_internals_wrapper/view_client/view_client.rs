use crate::near_internals_wrapper::view_client::{
    errors::{GetBlockError, QueryError, ViewClientError},
    request::ViewFunctionCall,
};

#[derive(Clone)]
pub(crate) struct ViewClientWrapper {
    view_client:
        near_async::multithread::MultithreadRuntimeHandle<near_client::ViewClientActorInner>,
}

impl ViewClientWrapper {
    pub(crate) fn new(
        view_client: near_async::multithread::MultithreadRuntimeHandle<
            near_client::ViewClientActorInner,
        >,
    ) -> Self {
        Self { view_client }
    }
    pub(crate) async fn latest_final_block(
        &self,
    ) -> Result<near_indexer_primitives::views::BlockView, ViewClientError> {
        let block_query =
            near_client::GetBlock(near_indexer_primitives::types::BlockReference::Finality(
                near_indexer_primitives::types::Finality::Final,
            ));
        let send_result =
            near_async::messaging::CanSendAsync::send_async(&self.view_client, block_query).await;
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
            block_reference: near_indexer_primitives::types::BlockReference::Finality(
                near_indexer_primitives::types::Finality::Final,
            ),
            request: request.into(),
        };
        let send_result =
            near_async::messaging::CanSendAsync::send_async(&self.view_client, query).await;
        let response_result = send_result.map_err(|err| QueryError::Send {
            op: request.clone(),
            source: Box::new(err),
        })?;
        let response = response_result.map_err(|err| QueryError::Response {
            op: request.clone(),
            source: Box::new(err),
        })?;
        match response.kind {
            near_indexer_primitives::views::QueryResponseKind::CallResult(call_result) => {
                Ok((response.block_height, call_result.result))
            }
            other => Err(QueryError::UnexpectedResponse {
                view_call: request.clone(),
                response: format!("{:?}", other),
            }
            .into()),
        }
    }
}
