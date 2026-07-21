use std::sync::Arc;

use near_account_id::AccountId;
use near_async::messaging::CanSendAsync as _;
use near_contract_transport::{BlockHeight, ObservedState, ViewArgs, ViewContract};

use crate::types::LatestFinalBlockInfo;
use crate::{
    errors::{NearViewClientError, NearViewClientQuery},
    primitives::FetchLatestFinalBlockInfo,
};

/// Arc-wrapper around near-internal struct
#[derive(Clone)]
pub(crate) struct NearViewClientActorHandle {
    view_client:
        Arc<near_async::multithread::MultithreadRuntimeHandle<near_client::ViewClientActor>>,
}

impl NearViewClientActorHandle {
    pub(crate) fn new(
        view_client: near_async::multithread::MultithreadRuntimeHandle<
            near_client::ViewClientActor,
        >,
    ) -> Self {
        Self {
            view_client: Arc::new(view_client),
        }
    }
}

impl ViewContract for NearViewClientActorHandle {
    type Error = NearViewClientError;
    type ObservedAt = BlockHeight;
    /// calls view method contract_id::method_name(args) and returns the result
    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        let method_name = view_args.method_name;
        let query = near_client::Query {
            block_reference: near_indexer_primitives::types::BlockReference::Finality(
                near_indexer_primitives::types::Finality::Final,
            ),
            request: near_indexer_primitives::views::QueryRequest::CallFunction {
                account_id: contract_id.clone(),
                method_name: method_name.clone(),
                args: view_args.args.into(),
            },
        };

        let send_result = self.view_client.send_async(query).await;

        let response_result = send_result.map_err(|err| NearViewClientError::AsyncSendError {
            query: NearViewClientQuery::ViewMethod {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
            },
            message: err.to_string(),
        })?;

        let response = response_result.map_err(|err| NearViewClientError::ResponseError {
            query: NearViewClientQuery::ViewMethod {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
            },
            message: err.to_string(),
        })?;

        let variant = match response.kind {
            near_indexer_primitives::views::QueryResponseKind::CallResult(call_result) => {
                return Ok(ObservedState {
                    observed_at: response.block_height.into(),
                    value: call_result.result,
                });
            }
            near_indexer_primitives::views::QueryResponseKind::ViewAccount(_) => "ViewAccount",
            near_indexer_primitives::views::QueryResponseKind::ViewCode(_) => "ViewCode",
            near_indexer_primitives::views::QueryResponseKind::ViewState(_) => "ViewState",
            near_indexer_primitives::views::QueryResponseKind::AccessKey(_) => "AccessKey",
            near_indexer_primitives::views::QueryResponseKind::AccessKeyList(_) => "AccessKeyList",
            near_indexer_primitives::views::QueryResponseKind::GasKeyNonces(_) => "GasKeyNonces",
        };

        Err(NearViewClientError::UnexpectedResponseError {
            query: NearViewClientQuery::ViewMethod {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
            },
            message: format!("expected CallResult, got {variant}"),
        })
    }
}

impl FetchLatestFinalBlockInfo for NearViewClientActorHandle {
    type Error = NearViewClientError;
    /// queries the near view client for the latest final block info
    async fn fetch_latest_final_block_info(&self) -> Result<LatestFinalBlockInfo, Self::Error> {
        let block_query =
            near_client::GetBlock(near_indexer_primitives::types::BlockReference::Finality(
                near_indexer_primitives::types::Finality::Final,
            ));
        let send_result = self.view_client.send_async(block_query).await;
        let response_result = send_result.map_err(|err| NearViewClientError::AsyncSendError {
            query: NearViewClientQuery::LatestFinalBlock,
            message: err.to_string(),
        })?;
        let response = response_result.map_err(|err| NearViewClientError::ResponseError {
            query: NearViewClientQuery::LatestFinalBlock,
            message: err.to_string(),
        })?;
        Ok(LatestFinalBlockInfo {
            observed_at: response.header.height.into(),
            value: response.header.hash,
        })
    }
}
