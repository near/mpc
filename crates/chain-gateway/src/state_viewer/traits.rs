use crate::errors::ChainGatewayError;
use crate::types::ObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::{Serialize, de::DeserializeOwned};

/// Trait abstracting the contract view call.
/// This allows testing the subscription/monitor logic without a real NEAR node.
#[async_trait]
pub trait ContractViewer: Send + Sync + Clone + 'static {
    async fn view(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, ChainGatewayError>;
}

pub trait HasContractViewer {
    type Viewer: ContractViewer;

    fn get_viewer(&self) -> &Self::Viewer;
}

#[async_trait]
pub trait ContractStateSubscriber: HasContractViewer {
    async fn subscribe<T>(
        &self,
        contract: AccountId,
        view_method: &str,
    ) -> impl ContractStateStream<T> + Send
    where
        T: DeserializeOwned + Send + Clone;
}

#[async_trait]
pub trait MethodViewer: HasContractViewer {
    async fn view<Arg, Res>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<ObservedState<Res>, ChainGatewayError>
    where
        Arg: Serialize + Sync,
        Res: DeserializeOwned + Send + Clone;
}

#[async_trait]
pub trait ContractStateStream<Res> {
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError>;
    /// Waits until the observed value changes.
    async fn changed(&mut self) -> Result<(), ChainGatewayError>;
}
