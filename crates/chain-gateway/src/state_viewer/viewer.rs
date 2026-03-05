use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::types::ObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;

use super::near_viewer::NearContractViewer;
use super::subscription::ContractMethodSubscription;
use super::traits::{
    ContractStateStream, ContractStateSubscriber, ContractViewer, HasContractViewer, MethodViewer,
};

/// External API for querying contract state. Generic over the viewer
/// implementation, defaulting to the real NEAR viewer.
///
/// External consumers should use `StateViewer` (without a type parameter),
/// which resolves to `StateViewer<NearContractViewer>`.
#[derive(Clone)]
pub struct StateViewer<V = NearContractViewer> {
    viewer: V,
}

impl<V> HasContractViewer for StateViewer<V>
where
    V: ContractViewer,
{
    type Viewer = V;

    fn get_viewer(&self) -> &Self::Viewer {
        &self.viewer
    }
}

impl<V: ContractViewer> StateViewer<V> {
    pub(crate) fn new(viewer: V) -> Self {
        Self { viewer }
    }
}

#[async_trait]
impl<T> ContractStateSubscriber for T
where
    T: HasContractViewer + Send + Sync,
{
    async fn subscribe<R>(
        &self,
        contract_id: AccountId,
        method_name: &str,
    ) -> impl ContractStateStream<R> + Send
    where
        R: DeserializeOwned + Send + Clone,
    {
        ContractMethodSubscription::new(
            self.get_viewer().clone(),
            contract_id,
            method_name,
            b"{}".to_vec(),
        )
        .await
    }
}

#[async_trait]
impl<T> MethodViewer for T
where
    T: HasContractViewer + Send + Sync,
{
    async fn view<Arg, Res>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<ObservedState<Res>, ChainGatewayError>
    where
        Arg: Serialize + Sync,
        Res: DeserializeOwned + Send + Clone,
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
        let res = self.get_viewer().view(&contract_id, method_name, &args).await?;
        let value = serde_json::from_slice::<Res>(&res.value).map_err(|err| {
            ChainGatewayError::Deserialization {
                source: Arc::new(err),
            }
        })?;

        Ok(ObservedState {
            observed_at: res.observed_at,
            value,
        })
    }
}
