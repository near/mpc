use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

use near_account_id::AccountId;
use serde::de::DeserializeOwned;
use std::{future::IntoFuture, pin::Pin};

use crate::FunctionCallArgs;
use crate::ViewArgs;
use crate::subscription::ContractMethodSubscription;
use crate::subscription::SubscriptionError;
use crate::subscription::ViewError;
use crate::subscription::WatchContractState;
use crate::subscription::deserialize_observed;
use crate::types::ObservedState;

#[must_use = "a ViewCall does nothing unless you call .get() or .subscribe()"]
pub struct ViewCall<V, T> {
    viewer: V,
    contract_id: AccountId,
    args: ViewArgs,
    _out: PhantomData<fn() -> T>,
}

impl<V, T> ViewCall<V, T> {
    pub fn new(viewer: V, contract_id: AccountId, args: ViewArgs) -> Self {
        Self {
            viewer,
            contract_id,
            args,
            _out: PhantomData,
        }
    }
}

impl<V, T> IntoFuture for ViewCall<V, T>
where
    V: ViewContract + Send + 'static,
    V::Error: ViewError,
    T: DeserializeOwned + 'static,
{
    type Output = Result<ObservedState<T>, SubscriptionError<V::Error>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.get())
    }
}

// one-shot: no PollInterval, no Send, no 'static
impl<V, T> ViewCall<V, T>
where
    V: ViewContract,
    V::Error: ViewError,
    T: DeserializeOwned,
{
    pub async fn get(self) -> Result<ObservedState<T>, SubscriptionError<V::Error>> {
        let raw = self
            .viewer
            .view_contract(&self.contract_id, self.args)
            .await
            .map_err(SubscriptionError::ViewError)?;
        deserialize_observed(raw)
    }
}

// polling: heavier bounds, confined to this block
impl<V, T> ViewCall<V, T>
where
    V: ViewContract + PollInterval + Send + 'static,
    V::Error: ViewError,
    T: DeserializeOwned + Send + Clone,
{
    pub async fn subscribe(self) -> impl WatchContractState<T, V::Error> + Send {
        ContractMethodSubscription::new(self.viewer, self.contract_id, self.args).await
    }
}
//impl<H: ViewContract> IntoFuture for ViewCall<H> {
//    type Output = Result<ObservedState<Vec<u8>>, H::Error>;
//    type IntoFuture = dyn Future<Output = Self::Output> + Send + 'a;
//    fn into_future(self) -> Self::IntoFuture {
//        self.handle.view_contract()
//    }
//}

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

pub trait PollInterval {
    fn poll_interval() -> Duration;
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
