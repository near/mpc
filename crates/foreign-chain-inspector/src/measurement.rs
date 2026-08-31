use std::sync::Arc;
use std::time::Duration;

use crate::ForeignChainInspectionError;

use super::ProviderId;

/// Times one provider call made by [`super::FanOut::extract`] and reports how long it took and how
/// it ended. Implemented by the node to record Prometheus metrics; the unit type implements it as
/// a no-op for fan-outs without measurement.
pub trait RecordProviderCall: Send + Sync {
    fn record(
        &self,
        chain: &str,
        provider: &ProviderId,
        elapsed: Duration,
        outcome: ProviderCallOutcome,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCallOutcome {
    Answered,
    Failed(ProviderFailure),
    /// The call was still in flight when the caller dropped the fan-out.
    Abandoned,
}

impl ProviderCallOutcome {
    fn of<T>(result: &Result<T, ForeignChainInspectionError>) -> Self {
        match result {
            Ok(_) => Self::Answered,
            Err(error) => error
                .provider_failure()
                .map_or(Self::Answered, Self::Failed),
        }
    }
}

/// Groups the ways a provider itself can fail, for callers that report an outcome rather than act
/// on it. Says nothing about retryability: see [`crate::ForeignChainInspectionError::is_transient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderFailure {
    /// No answer arrived: transport failure, 5xx, or rate limiting.
    Unreachable,
    /// The provider answered and refused. Retrying cannot change it.
    Rejected,
    /// The provider answered with something the caller could not use.
    Malformed,
    TimedOut,
}

#[derive(Clone)]
pub(crate) struct Measurement {
    pub(crate) chain: &'static str,
    pub(crate) record_call: Arc<dyn RecordProviderCall>,
}

/// Times one provider's call and reports it once, from [`Drop`]: a caller's deadline aborts the
/// spawned task mid-call, so no ordinary return path runs for a provider that never answers.
pub(crate) struct TimedCall {
    measurement: Option<Measurement>,
    provider: ProviderId,
    /// tokio's, so a paused clock in a test drives the reported duration.
    started: tokio::time::Instant,
    outcome: Option<ProviderCallOutcome>,
}

impl TimedCall {
    pub(crate) fn start(measurement: Option<Measurement>, provider: ProviderId) -> Self {
        Self {
            measurement,
            provider,
            started: tokio::time::Instant::now(),
            outcome: None,
        }
    }

    pub(crate) fn ended<T>(&mut self, result: &Result<T, ForeignChainInspectionError>) {
        self.outcome = Some(ProviderCallOutcome::of(result));
    }
}

impl Drop for TimedCall {
    fn drop(&mut self) {
        // A panicking inspector unwinds through this guard: the call was torn down, not
        // abandoned, and recording mid-unwind risks a double panic.
        if std::thread::panicking() {
            return;
        }
        let Some(measurement) = &self.measurement else {
            return;
        };
        measurement.record_call.record(
            measurement.chain,
            &self.provider,
            self.started.elapsed(),
            self.outcome.unwrap_or(ProviderCallOutcome::Abandoned),
        );
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordedCalls(std::sync::Mutex<Vec<ProviderCallOutcome>>);

    impl RecordProviderCall for RecordedCalls {
        fn record(
            &self,
            _chain: &str,
            _provider: &ProviderId,
            _elapsed: Duration,
            outcome: ProviderCallOutcome,
        ) {
            self.0.lock().unwrap().push(outcome);
        }
    }

    #[test]
    fn timed_call__should_report_nothing_while_its_task_is_panicking() {
        // Given
        let recorded = Arc::new(RecordedCalls::default());

        // When: the inspector panics, so the guard drops as part of the unwind.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _call = TimedCall::start(
                Some(Measurement {
                    chain: "testchain",
                    record_call: Arc::clone(&recorded) as Arc<dyn RecordProviderCall>,
                }),
                ProviderId("only".to_string()),
            );
            panic!("the inspector blew up");
        }));

        // Then
        assert!(panicked.is_err());
        assert_eq!(*recorded.0.lock().unwrap(), vec![]);
    }
}
