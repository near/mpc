use std::time::Duration;

use near_mpc_contract_interface::types::ProtocolContractState;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::ports::{ReadContractState, WatchContractState};

/// Observes the contract by re-reading it on a fixed interval, publishing a state only when it
/// differs from the last one. Wraps any [`ReadContractState`], so what is polled and how often
/// stays out of the service.
pub struct PollingContractStateWatcher {
    states: watch::Receiver<Observed>,
    cancel: CancellationToken,
    _poll_task: JoinHandle<()>,
}

impl PollingContractStateWatcher {
    /// Reads the contract once before returning, so the first [`WatchContractState::latest`] has
    /// a value to act on and a caller does not wait out a whole `poll_interval` at startup.
    pub async fn spawn<Reader>(
        reader: Reader,
        poll_interval: Duration,
        read_timeout: Duration,
    ) -> Self
    where
        Reader: ReadContractState + Send + Sync + 'static,
    {
        let (states, receiver) = watch::channel(read(&reader, read_timeout).await);
        let cancel = CancellationToken::new();
        let poll_task = tokio::spawn(poll(
            reader,
            poll_interval,
            read_timeout,
            states,
            cancel.clone(),
        ));

        Self {
            states: receiver,
            cancel,
            _poll_task: poll_task,
        }
    }
}

impl WatchContractState for PollingContractStateWatcher {
    type Error = PollError;

    fn latest(&mut self) -> Result<ProtocolContractState, Self::Error> {
        self.states.borrow_and_update().clone()
    }

    async fn changed(&mut self) -> Result<(), Self::Error> {
        self.states
            .changed()
            .await
            .map_err(|_| PollError::PollingStopped)
    }
}

/// Stops the polling task, which closes the channel and makes every later
/// [`WatchContractState::changed`] fail.
impl Drop for PollingContractStateWatcher {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Why the contract state could not be read
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PollError {
    #[error("could not read the contract state: {0}")]
    Read(String),

    #[error("reading the contract state did not finish within {0:?}")]
    Timeout(Duration),

    #[error("contract state polling has stopped")]
    PollingStopped,
}

type Observed = Result<ProtocolContractState, PollError>;

async fn poll<Reader: ReadContractState + Sync>(
    reader: Reader,
    poll_interval: Duration,
    read_timeout: Duration,
    states: watch::Sender<Observed>,
    cancel: CancellationToken,
) {
    let mut ticker = interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // `spawn` already read once to seed the channel.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let observed = read(&reader, read_timeout).await;
                if states.send_if_modified(|last| replace_if_different(last, observed)) {
                    tracing::debug!("observed a new contract state");
                }
            }
        }
    }
}

async fn read<Reader: ReadContractState + Sync>(
    reader: &Reader,
    read_timeout: Duration,
) -> Observed {
    match timeout(read_timeout, reader.get_contract_state()).await {
        Err(_elapsed) => Err(PollError::Timeout(read_timeout)),
        Ok(Err(err)) => Err(PollError::Read(format!("{err:?}"))),
        Ok(Ok(state)) => Ok(state),
    }
}

/// Overwrites `last` with `observed` when the two differ, reporting whether it did.
fn replace_if_different(last: &mut Observed, observed: Observed) -> bool {
    let different = *last != observed;
    if different {
        *last = observed;
    }
    different
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use rstest::rstest;

    use super::*;
    use crate::test_utils::must_get_running_state_with_epoch;

    const POLL_INTERVAL: Duration = Duration::from_secs(60);
    const READ_TIMEOUT: Duration = Duration::from_secs(30);

    /// Answers with the queued responses in order, repeating the last one once exhausted.
    struct FakeReader {
        responses: Mutex<VecDeque<Observed>>,
        last: Mutex<Option<Observed>>,
        hang: bool,
    }

    impl FakeReader {
        fn answering(responses: Vec<Observed>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                last: Mutex::new(None),
                hang: false,
            }
        }

        /// Accepts the read and never answers it.
        fn hanging() -> Self {
            Self {
                hang: true,
                ..Self::answering(vec![])
            }
        }
    }

    impl ReadContractState for FakeReader {
        type Error = PollError;

        async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
            if self.hang {
                std::future::pending::<()>().await;
            }
            let next = self.responses.lock().unwrap().pop_front();
            let mut last = self.last.lock().unwrap();
            if let Some(next) = next {
                *last = Some(next);
            }
            last.clone()
                .expect("a fake reader needs at least one response")
        }
    }

    fn read_error() -> Observed {
        Err(PollError::Read("mpc contract is unreachable".to_owned()))
    }

    #[rstest]
    #[case::unchanged_state(
        Ok(must_get_running_state_with_epoch(5)),
        Ok(must_get_running_state_with_epoch(5)),
        false
    )]
    #[case::changed_state(
        Ok(must_get_running_state_with_epoch(5)),
        Ok(must_get_running_state_with_epoch(6)),
        true
    )]
    #[case::repeated_failure(read_error(), read_error(), false)]
    #[case::started_failing(Ok(must_get_running_state_with_epoch(5)), read_error(), true)]
    #[case::recovered(read_error(), Ok(must_get_running_state_with_epoch(5)), true)]
    fn replace_if_different__should_replace_only_what_differs(
        #[case] mut last: Observed,
        #[case] observed: Observed,
        #[case] expected_replacement: bool,
    ) {
        // Given
        let before = last.clone();

        // When
        let replaced = replace_if_different(&mut last, observed.clone());

        // Then
        assert_eq!(replaced, expected_replacement);
        assert_eq!(
            last,
            if expected_replacement {
                observed
            } else {
                before
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn spawn__should_seed_the_first_state_before_any_poll() {
        // Given
        let state = must_get_running_state_with_epoch(5);
        let reader = FakeReader::answering(vec![Ok(state.clone())]);

        // When
        let mut watcher =
            PollingContractStateWatcher::spawn(reader, POLL_INTERVAL, READ_TIMEOUT).await;

        // Then
        assert_eq!(watcher.latest(), Ok(state));
    }

    #[tokio::test(start_paused = true)]
    async fn poll__should_publish_a_state_that_changed_since_the_last_read() {
        // Given
        let reshared = must_get_running_state_with_epoch(6);
        let reader = FakeReader::answering(vec![
            Ok(must_get_running_state_with_epoch(5)),
            Ok(reshared.clone()),
        ]);
        let mut watcher =
            PollingContractStateWatcher::spawn(reader, POLL_INTERVAL, READ_TIMEOUT).await;

        // When
        let changed = timeout(POLL_INTERVAL * 3, watcher.changed())
            .await
            .expect("the next poll should publish the new state");

        // Then
        assert_eq!(changed, Ok(()));
        assert_eq!(watcher.latest(), Ok(reshared));
    }

    #[tokio::test(start_paused = true)]
    async fn read__should_report_a_timeout_when_the_reader_never_answers() {
        // Given
        let reader = FakeReader::hanging();

        // When
        let mut watcher =
            PollingContractStateWatcher::spawn(reader, POLL_INTERVAL, READ_TIMEOUT).await;

        // Then
        assert_eq!(watcher.latest(), Err(PollError::Timeout(READ_TIMEOUT)));
    }

    #[tokio::test(start_paused = true)]
    async fn drop__should_stop_polling_and_fail_later_changes() {
        // Given
        let reader = FakeReader::answering(vec![Ok(must_get_running_state_with_epoch(5))]);
        let watcher = PollingContractStateWatcher::spawn(reader, POLL_INTERVAL, READ_TIMEOUT).await;
        let mut states = watcher.states.clone();

        // When
        drop(watcher);
        tokio::task::yield_now().await;

        // Then
        assert_eq!(
            states
                .changed()
                .await
                .map_err(|_| PollError::PollingStopped),
            Err(PollError::PollingStopped)
        );
    }
}
