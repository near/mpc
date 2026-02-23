use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{ClientWrapper, ViewClientWrapper, ViewFunctionCall};
use near_account_id::AccountId;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;

#[derive(Clone)]
pub struct ContractStateViewer {
    /// For querying blockchain sync status.
    pub(crate) client: Arc<ClientWrapper>,
    /// for viewing state
    pub(crate) view_client: Arc<ViewClientWrapper>,
    pub(crate) contract_id: AccountId,
}

impl ContractStateViewer {
    pub async fn view<T, U>(
        &self,
        method_name: &str,
        args: &T,
    ) -> Result<(u64, U), ChainGatewayError>
    where
        T: Serialize,
        U: DeserializeOwned,
    {
        self.client.wait_for_full_sync().await;
        let args: Vec<u8> = serde_json::to_string(args)
            .map_err(|err| ChainGatewayError::Serialization {
                op: ChainGatewayOp::ViewCall {
                    account_id: self.contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Box::new(err),
            })?
            .into_bytes();

        let (block_height, call_result) = self
            .view_client
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
            })?;
        let value = serde_json::from_slice::<U>(&call_result).map_err(|err| {
            ChainGatewayError::Deserialization {
                op: ChainGatewayOp::ViewCall {
                    account_id: self.contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Box::new(err),
            }
        })?;

        Ok((block_height, value))
    }
}
