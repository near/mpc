use std::sync::Arc;

use near_account_id::AccountId;
use near_async::messaging::CanSendAsync as _;
use near_indexer_primitives::types::{BlockId, BlockReference, Finality, SyncCheckpoint};
use near_kit_primitives::CryptoHash as KitCryptoHash;
use near_kit_primitives::rpc::{
    BlockReference as KitBlockReference, Finality as KitFinality,
    SyncCheckpoint as KitSyncCheckpoint, ViewFunctionResult,
};

use crate::types::LatestFinalBlockInfo;
use crate::{
    account_id_compat::to_near_internal,
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

impl NearViewClientActorHandle {
    /// calls view method contract_id::method_name(args) at `block` and returns the result
    pub(crate) async fn view_near(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
        block: KitBlockReference,
    ) -> Result<ViewFunctionResult, NearViewClientError> {
        let query = near_client::Query {
            block_reference: to_nearcore_block_reference(block),
            request: near_indexer_primitives::views::QueryRequest::CallFunction {
                account_id: to_near_internal(contract_id),
                method_name: method_name.to_string(),
                args: args.to_vec().into(),
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
                return Ok(ViewFunctionResult::new(
                    call_result.result,
                    response.block_height,
                    KitCryptoHash::from_bytes(response.block_hash.0),
                )
                .with_logs(call_result.logs));
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
            height: response.header.height.into(),
            hash: response.header.hash,
        })
    }
}

fn to_nearcore_block_reference(block: KitBlockReference) -> BlockReference {
    match block {
        KitBlockReference::Finality(KitFinality::Optimistic) => {
            BlockReference::Finality(Finality::None)
        }
        KitBlockReference::Finality(KitFinality::NearFinal) => {
            BlockReference::Finality(Finality::DoomSlug)
        }
        KitBlockReference::Finality(KitFinality::Final) => {
            BlockReference::Finality(Finality::Final)
        }
        KitBlockReference::Height(height) => BlockReference::BlockId(BlockId::Height(height)),
        KitBlockReference::Hash(hash) => BlockReference::BlockId(BlockId::Hash(
            near_indexer_primitives::CryptoHash(*hash.as_bytes()),
        )),
        KitBlockReference::SyncCheckpoint(KitSyncCheckpoint::Genesis) => {
            BlockReference::SyncCheckpoint(SyncCheckpoint::Genesis)
        }
        KitBlockReference::SyncCheckpoint(KitSyncCheckpoint::EarliestAvailable) => {
            BlockReference::SyncCheckpoint(SyncCheckpoint::EarliestAvailable)
        }
    }
}
