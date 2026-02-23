use near_account_id::AccountId;
use std::sync::Arc;

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{
    ClientWrapper, ViewClientWrapper, ViewFunctionCall,
};

use async_trait::async_trait;

pub type SharedContractViewer =
    Arc<dyn ContractViewMethodCaller<Error = ChainGatewayError> + Send + Sync>;

#[async_trait]
pub trait ContractViewMethodCaller: Send + Sync {
    type Error;
    async fn view(&self, method_name: &str, args: Vec<u8>) -> Result<(u64, Vec<u8>), Self::Error>;
}

pub(crate) struct ContractStateViewer {
    /// For querying blockchain sync status.
    pub(crate) client: ClientWrapper,
    /// for viewing state
    pub(crate) view_client: ViewClientWrapper,
    pub(crate) contract_id: AccountId,
}

#[async_trait]
impl ContractViewMethodCaller for ContractStateViewer {
    type Error = ChainGatewayError;
    async fn view(&self, method_name: &str, args: Vec<u8>) -> Result<(u64, Vec<u8>), Self::Error> {
        self.client.wait_for_full_sync().await;
        self.view_client
            .view_function_query(&ViewFunctionCall {
                account_id: self.contract_id.clone(),
                method_name: method_name.to_string(),
                args,
            })
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                // note: not sure we need to log account_id and method name here. It can be read in the boxed error
                op: ChainGatewayOp::ViewCall {
                    account_id: self.contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Box::new(err),
            })
    }
}
