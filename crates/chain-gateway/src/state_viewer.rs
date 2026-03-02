pub mod viewer_trait;
mod subscription;

pub use crate::near_internals_wrapper::BlockHeight;
pub use subscription::ContractStateStream;

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use near_account_id::AccountId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use subscription::ContractMethodSubscription;
use viewer_trait::{ContractViewer, NearContractViewer};

/// External API for querying contract state. Generic over the viewer
/// implementation, defaulting to the real NEAR viewer.
///
/// External consumers should use `StateViewer` (without a type parameter),
/// which resolves to `StateViewer<NearContractViewer>`.
pub struct StateViewer<V = NearContractViewer> {
    viewer: V,
}

impl<V: Clone> Clone for StateViewer<V> {
    fn clone(&self) -> Self {
        Self {
            viewer: self.viewer.clone(),
        }
    }
}

impl<V: ContractViewer> StateViewer<V> {
    pub(crate) fn new(viewer: V) -> Self {
        Self { viewer }
    }

    pub async fn subscribe_no_args<Res: DeserializeOwned + Send + Clone>(
        &self,
        contract_id: AccountId,
        method_name: &str,
    ) -> impl ContractStateStream<Res> {
        ContractMethodSubscription::new_internal(
            self.viewer.clone(),
            contract_id,
            method_name,
            b"{}".to_vec(),
        )
        .await
    }

    pub async fn subscribe<Arg: Serialize, Res: DeserializeOwned + Send + Clone>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<impl ContractStateStream<Res>, ChainGatewayError> {
        ContractMethodSubscription::new::<Arg, V>(
            self.viewer.clone(),
            contract_id,
            method_name,
            args,
        )
        .await
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
            .viewer
            .view_raw(&contract_id, method_name, &args)
            .await?;
        let value = serde_json::from_slice::<Res>(&res.value).map_err(|err| {
            ChainGatewayError::Deserialization {
                source: Arc::new(err),
            }
        })?;
        Ok((res.block_height, value))
    }
}
