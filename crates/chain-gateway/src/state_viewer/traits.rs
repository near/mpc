use crate::errors::ChainGatewayError;
use crate::types::ObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::{Serialize, de::DeserializeOwned};

/// The low-level testing seam for contract view calls.
#[async_trait]
pub trait ContractViewer: Send + Sync + Clone + 'static {
    async fn view(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, ChainGatewayError>;
}

/// Bridges a type to its [`ContractViewer`] implementation.
///
/// Implementing this trait automatically provides [`MethodViewer`] and
/// [`ContractStateSubscriber`] via blanket impls. Both [`super::NearContractViewer`]
/// and [`super::mock_viewer::MockViewer`] implement this with `type Viewer = Self`.
pub trait HasContractViewer {
    type Viewer: ContractViewer;

    fn get_viewer(&self) -> &Self::Viewer;
}

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
pub trait ContractStateSubscriber: HasContractViewer {
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
        T: DeserializeOwned + Send + Clone;
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
