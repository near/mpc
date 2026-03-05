use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{ClientWrapper, ViewClientWrapper};
use crate::types::ObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use std::sync::Arc;

use super::traits::ContractViewer;

#[derive(Clone)]
pub struct NearContractViewer {
    client: Arc<ClientWrapper>,
    view_client: Arc<ViewClientWrapper>,
}

impl NearContractViewer {
    pub(crate) fn new(client: Arc<ClientWrapper>, view_client: Arc<ViewClientWrapper>) -> Self {
        Self {
            client,
            view_client,
        }
    }
}

#[async_trait]
impl ContractViewer for NearContractViewer {
    /// Performs a view call against a NEAR contract.
    ///
    /// This methods awaits that the indexer is fully synced before issuing the request, which may
    /// take an unbounded amount of time.
    ///
    /// - `contract_id`: account ID of the contract to query
    /// - `method_name`: name of the view method to call
    /// - `args`: serialized method arguments
    ///
    /// Note: alternatively, we could return a "syncing" error instead of waiting for full sync.
    async fn view(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, ChainGatewayError> {
        self.client.wait_for_full_sync().await;
        self.view_client
            .view_function_query(contract_id, method_name, args)
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })
    }
}
