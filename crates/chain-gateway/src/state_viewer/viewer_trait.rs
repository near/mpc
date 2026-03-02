use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{
    ClientWrapper, ViewClientWrapper, ViewFunctionCall, ViewOutput,
};
use async_trait::async_trait;
use near_account_id::AccountId;
use std::sync::Arc;

/// Trait abstracting the raw contract view call.
/// This is the seam that allows testing the subscription/monitor logic
/// without a real NEAR node.
#[async_trait]
pub trait ContractViewer: Send + Sync + Clone + 'static {
    async fn view_raw(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ViewOutput, ChainGatewayError>;
}

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
    async fn view_raw(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ViewOutput, ChainGatewayError> {
        self.client.wait_for_full_sync().await;
        self.view_client
            .view_function_query(&ViewFunctionCall {
                account_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args: args.to_vec(),
            })
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
