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

impl RecordProviderCall for () {
    fn record(
        &self,
        _chain: &str,
        _provider: &ProviderId,
        _elapsed: Duration,
        _outcome: ProviderCallOutcome,
    ) {
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

pub(crate) struct Measurement<Recorder: RecordProviderCall> {
    pub(crate) chain: &'static str,
    pub(crate) record_call: Arc<Recorder>,
}

impl<Recorder: RecordProviderCall> Clone for Measurement<Recorder> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain,
            record_call: Arc::clone(&self.record_call),
        }
    }
}

/// Times one provider's call and reports it once, from [`Drop`]: a caller's deadline aborts the
/// spawned task mid-call, so no ordinary return path runs for a provider that never answers.
#[derive(Clone)]
pub(crate) struct TimedCall<Recorder: RecordProviderCall> {
    pub(crate) measurement: Option<Measurement<Recorder>>,
    pub(crate) provider: ProviderId,
    /// tokio's, so a paused clock in a test drives the reported duration.
    pub(crate) started: tokio::time::Instant,
    pub(crate) outcome: Option<ProviderCallOutcome>,
}

impl<Recorder: RecordProviderCall> TimedCall<Recorder> {
    pub(crate) fn start(measurement: Option<Measurement<Recorder>>, provider: ProviderId) -> Self {
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

impl<Recorder: RecordProviderCall> Drop for TimedCall<Recorder> {
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
    use crate::ForeignChainInspectionError;
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[derive(Default)]
    struct RecordedCalls(std::sync::Mutex<Vec<(String, ProviderId, ProviderCallOutcome)>>);

    impl RecordedCalls {
        fn taken(&self) -> Vec<(String, ProviderId, ProviderCallOutcome)> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    impl RecordProviderCall for RecordedCalls {
        fn record(
            &self,
            chain: &str,
            provider: &ProviderId,
            _elapsed: Duration,
            outcome: ProviderCallOutcome,
        ) {
            self.0
                .lock()
                .unwrap()
                .push((chain.to_owned(), provider.clone(), outcome));
        }
    }

    fn measured_call(recorded: &Arc<RecordedCalls>) -> TimedCall<RecordedCalls> {
        TimedCall::start(
            Some(Measurement {
                chain: "testchain",
                record_call: Arc::clone(recorded),
            }),
            ProviderId("only".to_string()),
        )
    }

    #[test]
    fn timed_call__should_report_the_outcome_the_call_ended_with() {
        // Given
        let recorded = Arc::new(RecordedCalls::default());
        let mut call = measured_call(&recorded);

        // When
        call.ended(&Err::<(), _>(ForeignChainInspectionError::Timeout));
        drop(call);

        // Then
        assert_eq!(
            recorded.taken(),
            vec![(
                "testchain".to_string(),
                ProviderId("only".to_string()),
                ProviderCallOutcome::Failed(ProviderFailure::TimedOut),
            )]
        );
    }

    #[test]
    fn timed_call__should_report_a_call_that_never_ended_as_abandoned() {
        // Given: a call whose task the caller's deadline aborted mid-flight.
        let recorded = Arc::new(RecordedCalls::default());
        let call = measured_call(&recorded);

        // When
        drop(call);

        // Then
        assert_matches!(
            recorded.taken()[..],
            [(_, _, ProviderCallOutcome::Abandoned)]
        );
    }

    #[test]
    fn timed_call__should_report_nothing_while_its_task_is_panicking() {
        // Given
        let recorded = Arc::new(RecordedCalls::default());

        // When: the inspector panics, so the guard drops as part of the unwind.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _call = measured_call(&recorded);
            panic!("the inspector blew up");
        }));

        // Then
        assert!(panicked.is_err());
        assert_eq!(recorded.taken(), vec![]);
    }

    #[rstest]
    #[case(Ok(()), ProviderCallOutcome::Answered)]
    #[case(
        Err(ForeignChainInspectionError::RpcRequestFailed("_".to_string())),
        ProviderCallOutcome::Failed(ProviderFailure::Unreachable)
    )]
    // A verdict about the transaction is an answer, so the provider is not at fault.
    #[case(
        Err(ForeignChainInspectionError::NotFinalized),
        ProviderCallOutcome::Answered
    )]
    fn provider_call_outcome_of__should_blame_the_provider_only_for_its_own_failures(
        #[case] result: Result<(), ForeignChainInspectionError>,
        #[case] expected: ProviderCallOutcome,
    ) {
        // When
        let outcome = ProviderCallOutcome::of(&result);

        // Then
        assert_eq!(outcome, expected);
    }
}
