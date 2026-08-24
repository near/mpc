use std::error::Error;

use crate::ObservedState;
use crate::TransportError;
use crate::monitoring::Observations;
use crate::traits::Decoder;

pub trait ViewError: Clone + Error + PartialEq + Send + Sync + 'static {}
impl<T: Clone + Error + PartialEq + Send + Sync + 'static> ViewError for T {}

/// A watch-like stream of contract state changes.
///
/// Call [`latest()`](WatchContractState::latest) to get the most recent value,
/// and [`changed()`](WatchContractState::changed) to wait for the next update.
/// Only actual value changes (different bytes) trigger a notification (block
/// height increases alone do not).
pub trait WatchContractState<T> {
    type Error;
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<T>, TransportError<Self::Error>>;
    /// Waits until the observed value changes.
    fn changed(&mut self) -> impl Future<Output = Result<(), TransportError<Self::Error>>> + Send;
}

/// Holds the observations and the latest cached value, so the same bytes are
/// not deserialized twice.
pub(crate) struct ContractMethodSubscription<T, E> {
    inner: Observations<E>,
    cached: Result<ObservedState<T>, TransportError<E>>,
    decoder: Decoder<T>,
}

fn decode<T, E>(
    observed: Result<ObservedState, E>,
    decoder: Decoder<T>,
) -> Result<ObservedState<T>, TransportError<E>> {
    observed
        .map_err(TransportError::ViewError)
        .and_then(|value| {
            decoder(value).map_err(|err| TransportError::Deserialization {
                message: err.to_string(),
            })
        })
}

impl<T, E> ContractMethodSubscription<T, E>
where
    E: ViewError,
{
    fn update_cache(&mut self) {
        let observed = self.inner.receiver_mut().borrow_and_update().clone();
        self.cached = decode(observed, self.decoder);
    }
}

impl<T, E> WatchContractState<T> for ContractMethodSubscription<T, E>
where
    T: Send + Clone,
    E: ViewError,
{
    type Error = E;
    async fn changed(&mut self) -> Result<(), TransportError<E>> {
        self.inner
            .receiver_mut()
            .changed()
            .await
            .map_err(|_| TransportError::MonitoringClosed)?;
        self.update_cache();
        Ok(())
    }

    fn latest(&mut self) -> Result<ObservedState<T>, TransportError<E>> {
        if self
            .inner
            .receiver_mut()
            .has_changed()
            .map_err(|_| TransportError::MonitoringClosed)?
        {
            self.update_cache();
        }
        self.cached.clone()
    }
}

impl<T, E> ContractMethodSubscription<T, E> {
    /// Marks the initial observation as seen, so
    /// [`changed`](WatchContractState::changed) will not fire until a genuinely
    /// new value arrives.
    pub(super) fn new(mut observations: Observations<E>, decoder: Decoder<T>) -> Self
    where
        E: ViewError,
    {
        let initial = observations.receiver_mut().borrow_and_update().clone();
        Self {
            cached: decode(initial, decoder),
            inner: observations,
            decoder,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use assert_matches::assert_matches;
    use near_account_id::AccountId;

    use crate::test_utils::{RecordingViewer, TestViewError};
    use crate::traits::ViewCall;
    use crate::types::{ObservedState, TransportError, ViewArgs};
    use crate::WatchContractState;

    const METHOD: &str = "get_value";

    fn contract() -> AccountId {
        "test.testnet".parse().unwrap()
    }

    fn json(observed_at: u64, value: &str) -> Result<ObservedState, TestViewError> {
        Ok(ObservedState {
            observed_at: observed_at.into(),
            value: serde_json::to_vec(value).unwrap(),
        })
    }

    /// Subscribes through the public path, so the decoder is wired the same way
    /// a caller gets it.
    async fn subscribed(
        initial: Result<ObservedState, TestViewError>,
    ) -> (
        RecordingViewer<TestViewError>,
        impl WatchContractState<String, Error = TestViewError>,
    ) {
        let viewer = RecordingViewer::answering(initial);
        let subscription = ViewCall::<_, String>::new(viewer.clone(), contract(), ViewArgs::no_args(METHOD))
            .subscribe()
            .await;
        (viewer, subscription)
    }

    #[tokio::test]
    async fn subscribe__should_decode_the_initial_observation() {
        // Given / When
        let (_viewer, mut subscription) = subscribed(json(42, "hello")).await;

        // Then
        let observed = subscription.latest().expect("the initial read succeeded");
        assert_eq!(observed.value, "hello");
        assert_eq!(observed.observed_at, 42.into());
    }

    #[tokio::test]
    async fn subscribe__should_surface_a_view_failure() {
        // Given / When
        let (_viewer, mut subscription) = subscribed(Err(TestViewError::First)).await;

        // Then
        assert_eq!(
            subscription.latest().unwrap_err(),
            TransportError::ViewError(TestViewError::First)
        );
    }

    #[tokio::test]
    async fn subscribe__should_surface_a_decode_failure() {
        // Given / When
        let (_viewer, mut subscription) = subscribed(Ok(ObservedState {
            observed_at: 1.into(),
            value: b"not json".to_vec(),
        }))
        .await;

        // Then
        assert_matches!(
            subscription.latest().unwrap_err(),
            TransportError::Deserialization { .. }
        );
    }

    #[tokio::test]
    async fn latest__should_return_the_value_observed_after_a_change() {
        // Given
        let (viewer, mut subscription) = subscribed(json(1, "initial")).await;
        assert_eq!(subscription.latest().unwrap().value, "initial");

        // When
        viewer.set_response_for(METHOD, json(2, "updated"));

        // Then
        let observed = subscription.latest().expect("the new value should decode");
        assert_eq!(observed.value, "updated");
        assert_eq!(observed.observed_at, 2.into());
    }

    /// `changed` decodes eagerly, so the `latest` that follows it costs nothing.
    /// Asserted by the backend not being read again.
    #[tokio::test]
    async fn changed__should_resolve_and_cache_the_new_value() {
        // Given
        let (viewer, mut subscription) = subscribed(json(1, "before")).await;
        assert_eq!(subscription.latest().unwrap().value, "before");
        viewer.set_response_for(METHOD, json(5, "after"));

        // When
        subscription.changed().await.expect("still observing");
        let reads_before_latest = viewer.calls().len();

        // Then
        let observed = subscription.latest().unwrap();
        assert_eq!(observed.value, "after");
        assert_eq!(observed.observed_at, 5.into());
        assert_eq!(
            viewer.calls().len(),
            reads_before_latest,
            "latest should read the cache, not the backend"
        );
    }

    /// A dropped producer must surface rather than hang.
    #[tokio::test]
    async fn changed__should_fail_once_nothing_publishes() {
        // Given
        let (viewer, mut subscription) = subscribed(json(1, "only")).await;

        // When
        drop(viewer);

        // Then
        assert_eq!(
            subscription.changed().await.unwrap_err(),
            TransportError::MonitoringClosed
        );
    }
}
