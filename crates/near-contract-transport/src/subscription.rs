use std::error::Error;

use crate::monitoring::{MonitoringTask, make_monitoring_task};
use crate::{ObservedState, ViewArgs, ViewContract, traits::PollInterval};

use near_account_id::AccountId;
use serde::de::DeserializeOwned;

pub trait ViewError: Clone + Error + PartialEq + Send + Sync + 'static {}
impl<T: Clone + Error + PartialEq + Send + Sync + 'static> ViewError for T {}

/// A watch-like stream of contract state changes.
///
/// Call [`latest()`](WatchContractState::latest) to get the most recent value,
/// and [`changed()`](WatchContractState::changed) to wait for the next update.
/// Only actual value changes (different bytes) trigger a notification (block
/// height increases alone do not).
pub trait WatchContractState<T, E> {
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<T>, SubscriptionError<E>>;
    /// Waits until the observed value changes.
    fn changed(&mut self) -> impl Future<Output = Result<(), SubscriptionError<E>>> + Send;
}

/// Holds a Monitoring task and the latest cached value.
/// This is useful such that we don't unnecessarily deserialize the same state multiple times.
pub(crate) struct ContractMethodSubscription<T, E> {
    inner: MonitoringTask<E>,
    cached: Result<ObservedState<T>, SubscriptionError<E>>,
}

impl<T, E> ContractMethodSubscription<T, E>
where
    T: DeserializeOwned,
    E: ViewError,
{
    fn update_cache(&mut self) {
        let observed = self.inner.last_observed.borrow_and_update().clone();
        self.cached = observed
            .map_err(|err| SubscriptionError::ViewError(err))
            .and_then(|value| deserialize_observed(value));
    }
}

impl<T, E> WatchContractState<T, E> for ContractMethodSubscription<T, E>
where
    T: DeserializeOwned + Send + Clone,
    E: ViewError,
{
    /// The constructor marks the initial value as seen, so
    /// `changed().await` will not fire until a genuinely new value arrives.
    async fn changed(&mut self) -> Result<(), SubscriptionError<E>> {
        self.inner
            .last_observed
            .changed()
            .await
            .map_err(|_| SubscriptionError::MonitoringClosed)?;
        self.update_cache();
        Ok(())
    }

    fn latest(&mut self) -> Result<ObservedState<T>, SubscriptionError<E>> {
        if self
            .inner
            .last_observed
            .has_changed()
            .map_err(|_| SubscriptionError::MonitoringClosed)?
        {
            self.update_cache();
        }
        self.cached.clone()
    }
}

impl<T, E> ContractMethodSubscription<T, E>
where
    T: DeserializeOwned,
{
    pub(super) async fn new<V>(viewer: V, contract_id: AccountId, view_args: ViewArgs) -> Self
    where
        V: ViewContract<Error = E> + PollInterval + Send + 'static,
        E: ViewError,
    {
        let mut task = make_monitoring_task(viewer, contract_id, view_args).await;
        let cached: Result<ObservedState<T>, SubscriptionError<E>> = task
            .last_observed
            .borrow_and_update()
            .clone()
            .map_err(|err| SubscriptionError::ViewError(err))
            .and_then(|value| deserialize_observed(value));
        Self {
            inner: task,
            cached,
        }
    }
}
// todo: move this somewhee better
pub(crate) fn deserialize_observed<T: DeserializeOwned, E>(
    observed: ObservedState,
) -> Result<ObservedState<T>, SubscriptionError<E>> {
    observed
        .deserialize()
        .map_err(|err| SubscriptionError::Deserialization {
            message: err.to_string(),
        })
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionError<E> {
    #[error("deserialization error: {message}")]
    Deserialization { message: String },

    #[error("monitoring task closed")]
    MonitoringClosed,

    #[error("View call failed: {0}")]
    ViewError(E),
}
