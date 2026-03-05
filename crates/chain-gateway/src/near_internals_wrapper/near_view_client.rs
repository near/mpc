use std::sync::Arc;

use near_account_id::AccountId;

use crate::{
    near_internals_wrapper::errors::{GetBlockError, QueryError, QueryErrorKind, ViewClientError},
    types::ObservedState,
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
            source: Arc::new(err),
        })?;
        let response = response_result.map_err(|err| GetBlockError::Response {
            source: Arc::new(err),
        })?;
        Ok(response)
    }

    pub(crate) async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, ViewClientError> {
        let query = near_client::Query {
            block_reference: near_indexer_primitives::types::BlockReference::Finality(
                near_indexer_primitives::types::Finality::Final,
            ),
            request: near_indexer_primitives::views::QueryRequest::CallFunction {
                account_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args: args.to_vec().into(),
            },
        };

        let send_result =
            near_async::messaging::CanSendAsync::send_async(&self.view_client, query).await;

        let response_result = send_result.map_err(|err| QueryError {
            contract_id: contract_id.clone(),
            method_name: method_name.to_string(),
            args: args.to_vec(),
            kind: QueryErrorKind::Send {
                source: Arc::new(err),
            },
        })?;

        let response = response_result.map_err(|err| QueryError {
            contract_id: contract_id.clone(),
            method_name: method_name.to_string(),
            args: args.to_vec(),
            kind: QueryErrorKind::Response {
                source: Arc::new(err),
            },
        })?;

        match response.kind {
            near_indexer_primitives::views::QueryResponseKind::CallResult(call_result) => {
                Ok(ObservedState {
                    observed_at: response.block_height.into(),
                    value: call_result.result,
                })
            }
            other => Err(QueryError {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args: args.to_vec(),
                kind: QueryErrorKind::UnexpectedResponse {
                    response: format!("{:?}", other),
                },
            }
            .into()),
        }
    }
}
