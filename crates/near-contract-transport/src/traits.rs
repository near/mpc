use std::future::Future;
use std::time::Duration;

use borsh::BorshDeserialize;
use near_account_id::AccountId;
use serde::de::DeserializeOwned;
use std::{future::IntoFuture, pin::Pin};

use crate::FunctionCallArgs;
use crate::TransportError;
use crate::ViewArgs;
use crate::monitoring::{Observations, poll_observations};
use crate::subscription::ContractMethodSubscription;
use crate::subscription::ViewError;
use crate::subscription::WatchContractState;
use crate::types::ObservedState;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("borsh: {0}")]
    Borsh(#[from] std::io::Error),
}

pub(crate) type Decoder<T> = fn(ObservedState<Vec<u8>>) -> Result<ObservedState<T>, DecodeError>;

fn decode_json<T: DeserializeOwned>(raw: ObservedState) -> Result<ObservedState<T>, DecodeError> {
    raw.deserialize::<T>().map_err(DecodeError::Json)
}

fn decode_borsh<T: BorshDeserialize>(raw: ObservedState) -> Result<ObservedState<T>, DecodeError> {
    raw.deserialize_borsh::<T>().map_err(DecodeError::Borsh)
}

#[must_use = "a ViewCall does nothing unless you call .get() or .subscribe()"]
pub struct ViewCall<V, T> {
    viewer: V,
    contract_id: AccountId,
    args: ViewArgs,
    decoder: Decoder<T>,
}

impl<V, T> ViewCall<V, T>
where
    T: DeserializeOwned,
{
    /// by defaults, decodes json
    pub fn new(viewer: V, contract_id: AccountId, args: ViewArgs) -> Self {
        Self {
            viewer,
            contract_id,
            args,
            decoder: decode_json::<T>,
        }
    }
}
impl<V, T> ViewCall<V, T>
where
    T: BorshDeserialize,
{
    pub fn borsh(viewer: V, contract_id: AccountId, args: ViewArgs) -> Self {
        Self {
            viewer,
            contract_id,
            args,
            decoder: decode_borsh::<T>,
        }
    }
}

impl<V, T> IntoFuture for ViewCall<V, T>
where
    V: ViewContract + Send + 'static,
    T: 'static,
{
    type Output = Result<ObservedState<T>, TransportError<V::Error>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.get())
    }
}

impl<V, T> ViewCall<V, T>
where
    V: ViewContract,
{
    async fn get(self) -> Result<ObservedState<T>, TransportError<V::Error>> {
        let raw = self
            .viewer
            .view_contract(&self.contract_id, self.args)
            .await
            .map_err(TransportError::ViewError)?;
        (self.decoder)(raw).map_err(|err| TransportError::Deserialization {
            message: err.to_string(),
        })
    }
}

impl<V, T> ViewCall<V, T>
where
    V: ObserveContract,
    V::Error: ViewError,
    T: Send + Clone,
{
    pub async fn subscribe(self) -> impl WatchContractState<T, Error = V::Error> + Send {
        let observations = self.viewer.observe(self.contract_id, self.args).await;
        ContractMethodSubscription::new(observations, self.decoder)
    }
}

pub trait CallContract {
    /// Backend-specific successful call outcome.
    type Output;
    type Error;

    fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}

impl<T: CallContract> CallContract for &T {
    type Output = T::Output;
    type Error = T::Error;

    fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send {
        T::call_contract(self, contract_id, call_args)
    }
}

/// A backend executing NEAR view calls against a contract.
///
/// Implementors wire [`ViewArgs`] to their transport (nearcore view client,
/// RPC, test double), convert the transport's observation height into
/// [`BlockHeight`](crate::BlockHeight), and surface its native error as
/// [`Error`](ViewContract::Error).
pub trait ViewContract {
    type Error;
    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState<Vec<u8>>, Self::Error>> + Send;
}

/// How often a [`ViewContract`] backend should be re-read. Implementing this
/// opts the backend into polling, which supplies [`ObserveContract`] for free.
///
/// A backend that publishes its own updates implements [`ObserveContract`]
/// directly and must not implement this.
pub trait PollInterval {
    fn poll_interval(&self) -> Duration;
}

/// A backend that can be watched, not just read.
///
/// Blanket-implemented for any [`ViewContract`] that reports a
/// [`PollInterval`]. Implement it directly only to replace polling with a
/// different notification mechanism.
pub trait ObserveContract: ViewContract {
    fn observe(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Observations<Self::Error>> + Send;
}

impl<T> ObserveContract for T
where
    T: ViewContract + PollInterval + Clone + Send + Sync + 'static,
    T::Error: ViewError,
{
    async fn observe(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> Observations<Self::Error> {
        poll_observations(self.clone(), contract_id, view_args, self.poll_interval()).await
    }
}

impl<T: ViewContract> ViewContract for &T {
    type Error = T::Error;

    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState<Vec<u8>>, Self::Error>> + Send {
        T::view_contract(self, contract_id, view_args)
    }
}
