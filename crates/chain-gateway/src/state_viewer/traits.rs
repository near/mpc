use std::sync::Arc;

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::traits::{SyncChecker, ViewFunctionQuerier};
use crate::types::ObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::{Serialize, de::DeserializeOwned};

use super::subscription::ContractMethodSubscription;

///// The testing seam for contract view calls
///// All other traits are derived from this one
//#[async_trait]
//pub trait ContractViewer: Send + Sync + Clone + 'static {
//    async fn view_raw(
//        &self,
//        contract_id: &AccountId,
//        method_name: &str,
//        args: &[u8],
//    ) -> Result<ObservedState, ChainGatewayError>;
//}

/// The testing seam for contract view calls
/// All other traits are derived from this one
#[async_trait]
pub trait ContractViewer:
    SyncChecker + ViewFunctionQuerier + Send + Sync + Clone + 'static
{
    async fn view_raw(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, ChainGatewayError> {
        self.wait_for_full_sync().await;
        self.view_function_query(contract_id, method_name, args)
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

///// Bridges a type to its [`ContractViewer`] implementation.
/////
///// Implementing this trait automatically provides [`MethodViewer`] and
///// [`ContractStateSubscriber`] via blanket impls. Both [`super::NearContractViewer`]
///// and [`super::mock_viewer::MockViewer`] implement this with `type Viewer = Self`.
//pub trait HasContractViewer {
//    type Viewer: ContractViewer;
//
//    fn get_viewer(&self) -> &Self::Viewer;
//}

/// Blanket-implemented for all `T: HasContractViewer`.
///
/// Provides a subscribe-and-poll interface for observing contract state changes.
/// Polls the view method every 200 ms and emits change notifications only when
/// the returned bytes differ.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "test-utils")]
/// # #[tokio::main]
/// # async fn main() {
/// use chain_gateway::state_viewer::{
///     mock_viewer::{MockViewer, Call},
///     ContractStateStream, ContractStateSubscriber,
/// };
/// use chain_gateway::types::ObservedState;
///
/// let viewer = MockViewer::new(
///     Call {
///         contract_id: "contract.near".parse().unwrap(),
///         method_name: "get_greeting".into(),
///         args: b"{}".to_vec(),
///     },
///     Ok(ObservedState {
///         observed_at: 1.into(),
///         value: br#""hello""#.to_vec(),
///     }),
/// );
///
/// let mut stream = viewer
///     .subscribe::<String>("contract.near".parse().unwrap(), "get_greeting")
///     .await;
///
/// let state = stream.latest().unwrap();
/// assert_eq!(state.value, "hello");
/// # }
/// ```
#[async_trait]
pub trait ContractStateSubscriber: ContractViewer {
    /// Subscribes to a contract view method and returns a stream of state updates.
    ///
    /// The returned stream polls the contract every 200 ms.
    ///
    /// # Type Parameter
    ///
    /// `T` is the deserialized return type of the contract method.
    async fn subscribe<T>(
        &self,
        contract: AccountId,
        view_method: &str,
    ) -> impl ContractStateStream<T> + Send
    where
        T: DeserializeOwned + Send + Clone,
    {
        ContractMethodSubscription::new(self.clone(), contract, &view_method, b"{}".to_vec()).await
    }
}

/// Blanket-implemented for all `T: HasContractViewer`.
///
/// Performs a one-shot typed view call: serializes `args` as JSON, calls the
/// underlying [`ContractViewer::view`], and deserializes the response.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "test-utils")]
/// # #[tokio::main]
/// # async fn main() {
/// use chain_gateway::state_viewer::{
///     mock_viewer::{MockViewer, Call},
///     MethodViewer,
/// };
/// use chain_gateway::types::{NoArgs, ObservedState};
///
/// let viewer = MockViewer::new(
///     Call {
///         contract_id: "contract.near".parse().unwrap(),
///         method_name: "get_greeting".into(),
///         args: b"{}".to_vec(),
///     },
///     Ok(ObservedState {
///         observed_at: 1.into(),
///         value: br#""hello""#.to_vec(),
///     }),
/// );
///
/// let result: ObservedState<String> = viewer
///     .view("contract.near".parse().unwrap(), "get_greeting", &NoArgs {})
///     .await
///     .unwrap();
///
/// assert_eq!(result.value, "hello");
/// assert_eq!(result.observed_at, 1.into());
/// # }
/// ```
#[async_trait]
pub trait MethodViewer: ContractViewer {
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
        let res = self.view_raw(&contract_id, method_name, &args).await?;
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

/// A watch-like stream of contract state changes.
///
/// Call [`latest()`](ContractStateStream::latest) to get the most recent value,
/// and [`changed()`](ContractStateStream::changed) to wait for the next update.
/// Only actual value changes (different bytes) trigger a notification (block
/// height increases alone do not).
#[async_trait]
pub trait ContractStateStream<Res> {
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError>;
    /// Waits until the observed value changes.
    async fn changed(&mut self) -> Result<(), ChainGatewayError>;
}
