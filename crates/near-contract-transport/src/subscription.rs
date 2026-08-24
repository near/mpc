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
