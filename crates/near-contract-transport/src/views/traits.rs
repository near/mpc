use std::time::Duration;

use near_account_id::AccountId;

use crate::{
    TransportError,
    views::{
        args::ViewArgs,
        deserialize::DeserializeAs,
        errors::WaitError,
        observation::{ObservedState, SerializedObservation},
        view_call::ViewCall,
    },
};

/// A backend executing NEAR view calls against a contract.
///
/// A back-end implementing this trait inherits the deserializing one-shot
/// views ([`view`](ViewContract::view)) and the subscription logic
/// ([`WatchContractState`]).
pub trait ViewContract {
    type Error: std::error::Error + Clone + PartialEq + Send + Sync + 'static;

    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<SerializedObservation, Self::Error>> + Send;

    /// Views `contract_id` and decodes the result to `T` with the deserializer
    /// selected by `D`, e.g. `gateway.view::<Foo, Json>(id, args)`.
    fn view<T, D>(&self, contract_id: AccountId, args: ViewArgs) -> ViewCall<Self, T>
    where
        D: DeserializeAs<T>,
        Self: Clone + Sized,
    {
        ViewCall::new::<D>(self.clone(), contract_id, args)
    }
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
pub trait WatchContractState {
    type Value;
    type ViewError;

    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<Self::Value>, TransportError<Self::ViewError>>;
    /// Waits until the observed value changes.
    fn changed(
        &mut self,
    ) -> impl Future<Output = Result<(), TransportError<Self::ViewError>>> + Send;

    /// Waits until the observed value satisfies `predicate` and returns that observation.
    ///
    /// Errors from [`latest()`](WatchContractState::latest) are treated as transient and skipped;
    /// only [`changed()`](WatchContractState::changed) failing ends the wait early.
    fn wait_for(
        &mut self,
        timeout: Duration,
        mut predicate: impl FnMut(&Self::Value) -> bool + Send,
    ) -> impl Future<Output = Result<ObservedState<Self::Value>, WaitError<Self::ViewError>>> + Send
    where
        Self: Send,
    {
        async move {
            tokio::time::timeout(timeout, async {
                loop {
                    if let Ok(observed) = self.latest()
                        && predicate(&observed.value)
                    {
                        return Ok(observed);
                    }
                    self.changed().await?;
                }
            })
            .await
            .map_err(|_elapsed| WaitError::TimedOut(timeout))?
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{PollInterval, WatchContractState};
    use crate::{ObservedState, TransportError, WaitError};
    use rstest::rstest;
    use std::{collections::VecDeque, time::Duration};

    type Observation = Result<ObservedState<&'static str>, TransportError<&'static str>>;
    type WaitResult = Result<ObservedState<&'static str>, WaitError<&'static str>>;

    struct ScriptedWatch {
        observations: VecDeque<Observation>,
        closes: bool,
    }

    impl WatchContractState for ScriptedWatch {
        type Value = &'static str;
        type ViewError = &'static str;

        fn latest(&mut self) -> Observation {
            self.observations
                .front()
                .cloned()
                .expect("script exhausted")
        }

        async fn changed(&mut self) -> Result<(), TransportError<&'static str>> {
            if self.observations.len() > 1 {
                self.observations.pop_front();
                return Ok(());
            }
            if self.closes {
                return Err(TransportError::MonitoringClosed);
            }
            std::future::pending().await
        }
    }

    fn observed(observed_at: u64, value: &'static str) -> Observation {
        Ok(ObservedState {
            observed_at: observed_at.into(),
            value,
        })
    }

    #[test]
    fn poll_interval_new__should_reject_zero() {
        assert!(PollInterval::new(Duration::ZERO).is_none());
    }

    #[rstest]
    #[case::returns_an_observation_that_already_satisfies_the_predicate(
        vec![observed(1, "ready")],
        Duration::from_secs(10),
        "ready",
        observed(1, "ready").map_err(WaitError::Transport)
    )]
    #[case::returns_the_first_observation_satisfying_the_predicate(
        vec![observed(1, "a"), observed(2, "b"), observed(3, "b")],
        Duration::from_secs(10),
        "b",
        observed(2, "b").map_err(WaitError::Transport)
    )]
    #[case::skips_view_errors(
        vec![Err(TransportError::View("view failed")), observed(2, "recovered")],
        Duration::from_secs(10),
        "recovered",
        observed(2, "recovered").map_err(WaitError::Transport)
    )]
    #[case::accepts_an_unbounded_timeout(
        vec![observed(1, "a"), observed(2, "b")],
        Duration::MAX,
        "b",
        observed(2, "b").map_err(WaitError::Transport)
    )]
    #[case::fails_when_the_subscription_closes(
        vec![observed(1, "value")],
        Duration::from_secs(10),
        "never",
        Err(WaitError::Transport(TransportError::MonitoringClosed))
    )]
    #[tokio::test]
    async fn wait_for__should_resolve_against_a_closing_subscription(
        #[case] observations: Vec<Observation>,
        #[case] timeout: Duration,
        #[case] target: &'static str,
        #[case] expected: WaitResult,
    ) {
        // Given
        let mut watch = ScriptedWatch {
            observations: observations.into(),
            closes: true,
        };

        // When
        let result = watch.wait_for(timeout, |value| *value == target).await;

        // Then
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::keeps_waiting_while_view_errors_persist(Err(TransportError::View("view failed")))]
    #[case::times_out_when_the_predicate_never_holds(observed(1, "value"))]
    #[tokio::test(start_paused = true)]
    async fn wait_for__should_time_out_on_an_open_subscription(#[case] observation: Observation) {
        // Given
        let mut watch = ScriptedWatch {
            observations: [observation].into(),
            closes: false,
        };
        let timeout = Duration::from_secs(1);

        // When
        let result = watch.wait_for(timeout, |value| *value == "never").await;

        // Then
        assert_eq!(result, Err(WaitError::TimedOut(timeout)));
    }
}
