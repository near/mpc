use std::time::Duration;

use near_account_id::AccountId;

use crate::{
    TransportError,
    views::{
        args::ViewArgs,
        observation::{ObservedState, SerializedObservation},
    },
};

/// A backend executing NEAR view calls against a contract.
///
/// Implementors wire [`ViewArgs`] to their transport (nearcore view client,
/// RPC, test double) and surface the transport's native error as
/// [`Error`](ViewContract::Error).
pub trait ViewContract {
    type Error: std::error::Error + Clone + PartialEq + Send + Sync + 'static;

    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<SerializedObservation, Self::Error>> + Send;
}

/// A non-zero polling period.
/// Zero is rejected because subscriptions feed this to `tokio::time::interval`, which panics on zero.
#[derive(Debug, Clone, Copy)]
pub struct PollInterval(Duration);

impl PollInterval {
    pub fn new(duration: Duration) -> Option<Self> {
        (!duration.is_zero()).then_some(Self(duration))
    }
}

impl From<PollInterval> for Duration {
    fn from(interval: PollInterval) -> Self {
        interval.0
    }
}

pub trait HasPollInterval {
    fn poll_interval(&self) -> PollInterval;
}

/// A stream of contract state changes.
///
/// Call [`latest()`](WatchContractState::latest) to get the most recent value,
/// and [`changed()`](WatchContractState::changed) to wait for the next update.
///
/// The returned block-height in [`ObservedState`] is the height at which this value was first seen.
pub trait WatchContractState<T, ViewError> {
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<T>, TransportError<ViewError>>;
    /// Waits until the observed value changes.
    fn changed(&mut self) -> impl Future<Output = Result<(), TransportError<ViewError>>> + Send;
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::PollInterval;
    use std::time::Duration;

    #[test]
    fn poll_interval_new__should_reject_zero() {
        assert!(PollInterval::new(Duration::ZERO).is_none());
    }
}
