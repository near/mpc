use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{
    BlockHeight, ClientWrapper, ViewClientWrapper, ViewFunctionCall, ViewOutput,
};
use near_account_id::AccountId;
use serde::Serialize;
use serde::de::DeserializeOwned;

use std::sync::Arc;

#[derive(Clone)]
pub struct StateViewer {
    /// For querying blockchain sync status.
    pub(crate) client: Arc<ClientWrapper>,
    /// for viewing state
    pub(crate) view_client: Arc<ViewClientWrapper>,
}

impl StateViewer {
    pub async fn view_raw(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<ViewOutput, ChainGatewayError> {
        self.client.wait_for_full_sync().await;
        let response = self
            .view_client
            .view_function_query(&ViewFunctionCall {
                account_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args,
            })
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                // note: not sure we need to log account_id and method name here. It can be read in the boxed error
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })?;
        Ok(response)
    }

    pub async fn view<Arg, Res>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<(BlockHeight, Res), ChainGatewayError>
    where
        Arg: Serialize,
        Res: DeserializeOwned,
    {
        let args: Vec<u8> = serde_json::to_string(args)
            .map_err(|err| ChainGatewayError::Serialization {
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })?
            .into_bytes();
        let res = self
            .view_raw(contract_id.clone(), method_name, args)
            .await?;
        let value = serde_json::from_slice::<Res>(&res.value).map_err(|err| {
            ChainGatewayError::Deserialization {
                source: Arc::new(err),
            }
        })?;
        Ok((res.block_height, value))
    }
}
