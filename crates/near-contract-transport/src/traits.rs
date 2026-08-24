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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use assert_matches::assert_matches;
    use near_account_id::AccountId;

    use super::ViewCall;
    use crate::test_utils::{RecordingViewer, TestViewError, ViewRequest};
    use crate::types::{ObservedState, TransportError, ViewArgs};

    const METHOD: &str = "get_value";

    fn contract() -> AccountId {
        "test.testnet".parse().unwrap()
    }

    fn viewer(response: Result<ObservedState, TestViewError>) -> RecordingViewer<TestViewError> {
        RecordingViewer::answering(response)
    }

    #[tokio::test]
    async fn view_call__should_ask_the_backend_for_the_requested_method_and_args() {
        // Given
        let backend = viewer(Ok(ObservedState {
            observed_at: 1.into(),
            value: serde_json::to_vec("value").unwrap(),
        }));
        let args = vec![0xAA, 0xBB];

        // When
        let _ = ViewCall::<_, String>::new(
            backend.clone(),
            contract(),
            ViewArgs::new(METHOD, args.clone()),
        )
        .await;

        // Then
        assert_eq!(
            backend.calls(),
            vec![ViewRequest {
                contract_id: contract(),
                method_name: METHOD.to_string(),
                args,
            }]
        );
    }

    #[tokio::test]
    async fn view_call__should_decode_a_json_response() {
        // Given
        let backend = viewer(Ok(ObservedState {
            observed_at: 7.into(),
            value: serde_json::to_vec("decoded").unwrap(),
        }));

        // When
        let observed = ViewCall::<_, String>::new(backend, contract(), ViewArgs::no_args(METHOD))
            .await
            .expect("a well-formed response should decode");

        // Then
        assert_eq!(observed.value, "decoded");
        assert_eq!(observed.observed_at, 7.into());
    }

    #[tokio::test]
    async fn view_call__should_surface_the_backend_failure_unchanged() {
        // Given
        let backend = viewer(Err(TestViewError::Second));

        // When
        let err = ViewCall::<_, String>::new(backend, contract(), ViewArgs::no_args(METHOD))
            .await
            .expect_err("a failing backend should fail the call");

        // Then
        assert_eq!(err, TransportError::ViewError(TestViewError::Second));
    }

    #[tokio::test]
    async fn view_call__should_report_a_response_it_cannot_decode() {
        // Given
        let backend = viewer(Ok(ObservedState {
            observed_at: 1.into(),
            value: b"not json".to_vec(),
        }));

        // When
        let err = ViewCall::<_, String>::new(backend, contract(), ViewArgs::no_args(METHOD))
            .await
            .expect_err("undecodable bytes should fail the call");

        // Then
        assert_matches!(err, TransportError::Deserialization { .. });
    }

    /// The contract's only borsh view proves the decoder is selectable.
    #[tokio::test]
    async fn view_call__should_decode_a_borsh_response() {
        // Given
        let backend = viewer(Ok(ObservedState {
            observed_at: 3.into(),
            value: borsh::to_vec(&7u64).unwrap(),
        }));

        // When
        let observed = ViewCall::<_, u64>::borsh(backend, contract(), ViewArgs::no_args(METHOD))
            .await
            .expect("a well-formed borsh response should decode");

        // Then
        assert_eq!(observed.value, 7);
    }
}
