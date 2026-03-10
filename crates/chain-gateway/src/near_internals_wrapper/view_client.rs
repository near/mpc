use std::sync::Arc;

use near_account_id::AccountId;
use near_async::messaging::CanSendAsync as _;

use crate::{
    errors::{
        NearViewClientError, NearViewClientErrorKind, UnexpectedResponseError, ViewClientQuery,
    },
    primitives::ViewFunctionQuerySubmitter,
    types::ObservedState,
};

/// Arc-wrapper around near-internal ViewClientActor
#[derive(Clone)]
pub(crate) struct ViewClientWrapper {
    view_client:
        Arc<near_async::multithread::MultithreadRuntimeHandle<near_client::ViewClientActorInner>>,
}

impl ViewClientWrapper {
    pub(crate) fn new(
        view_client: near_async::multithread::MultithreadRuntimeHandle<
            near_client::ViewClientActorInner,
        >,
    ) -> Self {
        Self {
            view_client: Arc::new(view_client),
        }
    }
}

impl ViewFunctionQuerySubmitter for ViewClientWrapper {
    type Error = NearViewClientError;
    /// calls view method contract_id::method_name(args) and returns the result
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, Self::Error> {
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

        let send_result = self.view_client.send_async(query).await;

        let response_result = send_result.map_err(|err| NearViewClientError {
            query: ViewClientQuery::ViewMethod {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
            },
            kind: NearViewClientErrorKind::SendError,
            source: Arc::new(err),
        })?;

        let response = response_result.map_err(|err| NearViewClientError {
            query: ViewClientQuery::ViewMethod {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
            },
            kind: NearViewClientErrorKind::ResponseError,
            source: Arc::new(err),
        })?;

        match response.kind {
            near_indexer_primitives::views::QueryResponseKind::CallResult(call_result) => {
                Ok(ObservedState {
                    observed_at: response.block_height.into(),
                    value: call_result.result,
                })
            }
            other => Err(NearViewClientError {
                query: ViewClientQuery::ViewMethod {
                    contract_id: contract_id.clone(),
                    method_name: method_name.to_string(),
                },
                kind: NearViewClientErrorKind::UnexpectedResponse,
                source: Arc::new(UnexpectedResponseError(format!("{:?}", other))),
            }),
        }
    }
}
