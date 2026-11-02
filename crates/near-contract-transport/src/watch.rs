use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use near_kit_primitives::rpc::ViewFunctionResult;
use near_kit_primitives::{ContractError, View, Viewer};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

/// The latest outcome of a polled view: the decoded value with the block it
/// was first seen at, or the error the last poll failed with.
pub type Observed<T, E> = Result<ViewFunctionResult<T>, Arc<E>>;

/// Polls a contract view into a [`watch`] channel of its changes, e.g.
/// `mpc_contract.state().subscribe(poll_interval).await`.
pub trait Subscribe {
    type Value;
    type Error;

    /// Runs the view now and then every `interval`, publishing an outcome
    /// only when it differs from the last one: different bytes from the
    /// contract (decoded only then, so an unchanged value keeps the block it
    /// was first seen at), a different error, or a switch between the two.
    /// Polling stops once every receiver is dropped.
    fn subscribe(
        self,
        interval: Duration,
    ) -> impl Future<Output = watch::Receiver<Observed<Self::Value, Self::Error>>> + Send;
}

impl<C, T> Subscribe for View<C, T>
where
    C: Viewer<ViewError: Display + Send + Sync + 'static> + Clone + Send + Sync + 'static,
    T: Send + Sync + 'static,
{
    type Value = T;
    type Error = ContractError<C::ViewError>;

    async fn subscribe(self, interval: Duration) -> watch::Receiver<Observed<T, Self::Error>> {
        let mut poller = Poller {
            view: self,
            last_bytes: None,
        };
        let first = poller
            .poll()
            .await
            .expect("the first answer has nothing to compare with");
        let (sender, receiver) = watch::channel(first);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                tokio::select! {
                    () = sender.closed() => break,
                    _ = ticker.tick() => {}
                }
                let Some(next) = poller.poll().await else {
                    continue;
                };
                sender.send_if_modified(|current| {
                    let changed = match (&*current, &next) {
                        (Err(old), Err(new)) => old.to_string() != new.to_string(),
                        _ => true,
                    };
                    if changed {
                        *current = next;
                    }
                    changed
                });
            }
        });
        receiver
    }
}

/// Runs a view, decoding its answer only when the bytes changed.
struct Poller<C, T> {
    view: View<C, T>,
    /// The bytes of the value last published, or `None` after an error.
    last_bytes: Option<Vec<u8>>,
}

impl<C: Viewer + Clone, T> Poller<C, T> {
    /// The view's outcome, or `None` when the contract returned the same
    /// bytes as the value last published.
    async fn poll(&mut self) -> Option<Observed<T, ContractError<C::ViewError>>> {
        let raw = match self.view.clone().fetch_raw().await {
            Ok(raw) => raw,
            Err(error) => {
                self.last_bytes = None;
                return Some(Err(Arc::new(error)));
            }
        };
        if self.last_bytes.as_ref() == Some(&raw.result) {
            return None;
        }
        let outcome = match self.view.decode(&raw.result) {
            Ok(value) => {
                let observed = ViewFunctionResult::new(value, raw.block_height, raw.block_hash)
                    .with_logs(raw.logs);
                self.last_bytes = Some(raw.result);
                Ok(observed)
            }
            Err(error) => {
                self.last_bytes = None;
                Err(Arc::new(ContractError::Codec(error)))
            }
        };
        Some(outcome)
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WaitError {
    #[error("predicate not satisfied within {0:?}")]
    TimedOut(Duration),
    #[error("the view stopped being polled")]
    Closed,
}

/// Waits until the watched value satisfies `predicate` and returns that
/// observation. Errors are skipped: only a closed watch or `timeout` ends the
/// wait early.
pub async fn wait_for<T: Clone, E>(
    receiver: &mut watch::Receiver<Observed<T, E>>,
    timeout: Duration,
    mut predicate: impl FnMut(&T) -> bool,
) -> Result<ViewFunctionResult<T>, WaitError> {
    let matched = tokio::time::timeout(
        timeout,
        receiver.wait_for(|observed| observed.as_ref().is_ok_and(|o| predicate(&o.result))),
    )
    .await
    .map_err(|_elapsed| WaitError::TimedOut(timeout))?
    .map_err(|_closed| WaitError::Closed)?;
    let Ok(observed) = &*matched else {
        unreachable!("the predicate only matches values")
    };
    Ok(observed.clone())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{Subscribe, WaitError, wait_for};
    use near_kit_primitives::rpc::{BlockReference, ViewFunctionResult};
    use near_kit_primitives::{AccountId, CryptoHash, View, Viewer};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const INTERVAL: Duration = Duration::from_millis(10);

    /// The bytes a view returns and the block they were read at, or an error.
    type Answer = Result<(&'static str, u64), &'static str>;

    /// A backend answering from a script in order, then repeating the last
    /// answer.
    #[derive(Clone)]
    struct Scripted {
        script: Arc<Mutex<VecDeque<Answer>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Scripted {
        fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
            Self {
                script: Arc::new(Mutex::new(answers.into_iter().collect())),
                calls: Arc::default(),
            }
        }

        fn view(&self) -> View<Self, u32> {
            let contract_id: AccountId = "contract.near".parse().unwrap();
            View::json(self.clone(), contract_id, "value")
        }
    }

    impl Viewer for Scripted {
        type ViewError = String;

        async fn view_function(
            &self,
            _contract_id: &AccountId,
            _method: &str,
            _args: &[u8],
            _block: BlockReference,
        ) -> Result<ViewFunctionResult, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = {
                let mut script = self.script.lock().unwrap();
                if script.len() > 1 {
                    script.pop_front().unwrap()
                } else {
                    *script.front().unwrap()
                }
            };
            answer
                .map(|(bytes, height)| {
                    ViewFunctionResult::new(bytes.as_bytes().to_vec(), height, CryptoHash::ZERO)
                })
                .map_err(str::to_string)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn subscribe__should_start_with_the_first_answer() {
        let receiver = Scripted::new([Ok(("1", 10))])
            .view()
            .subscribe(INTERVAL)
            .await;
        let observed = receiver.borrow().clone().unwrap();
        assert_eq!((observed.result, observed.block_height), (1, 10));
    }

    #[tokio::test(start_paused = true)]
    async fn subscribe__should_publish_changed_bytes_and_keep_the_first_height_of_unchanged_ones() {
        let mut receiver =
            Scripted::new([Ok(("1", 10)), Ok(("1", 11)), Ok(("2", 12)), Ok(("2", 13))])
                .view()
                .subscribe(INTERVAL)
                .await;

        receiver.changed().await.unwrap();
        let observed = receiver.borrow_and_update().clone().unwrap();
        assert_eq!((observed.result, observed.block_height), (2, 12));

        tokio::time::sleep(INTERVAL * 5).await;
        assert!(!receiver.has_changed().unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn subscribe__should_publish_errors_and_recoveries() {
        let mut receiver = Scripted::new([Ok(("1", 10)), Err("down"), Ok(("1", 12))])
            .view()
            .subscribe(INTERVAL)
            .await;

        receiver.changed().await.unwrap();
        assert_eq!(
            receiver
                .borrow_and_update()
                .as_ref()
                .unwrap_err()
                .to_string(),
            "down"
        );
        receiver.changed().await.unwrap();
        assert_eq!(
            receiver.borrow_and_update().as_ref().unwrap().block_height,
            12
        );
    }

    #[tokio::test(start_paused = true)]
    async fn subscribe__should_publish_an_answer_that_fails_to_decode_as_an_error() {
        let mut receiver = Scripted::new([Ok(("1", 10)), Ok(("\"one\"", 11)), Ok(("1", 12))])
            .view()
            .subscribe(INTERVAL)
            .await;

        receiver.changed().await.unwrap();
        assert!(receiver.borrow_and_update().is_err());
        receiver.changed().await.unwrap();
        let observed = receiver.borrow_and_update().clone().unwrap();
        assert_eq!((observed.result, observed.block_height), (1, 12));
    }

    #[tokio::test(start_paused = true)]
    async fn subscribe__should_stop_polling_once_every_receiver_is_dropped() {
        let backend = Scripted::new([Ok(("0", 0))]);
        let receiver = backend.view().subscribe(INTERVAL).await;
        tokio::time::sleep(INTERVAL * 3).await;

        drop(receiver);
        tokio::time::sleep(INTERVAL).await;
        let after_drop = backend.calls.load(Ordering::SeqCst);
        tokio::time::sleep(INTERVAL * 5).await;

        assert_eq!(backend.calls.load(Ordering::SeqCst), after_drop);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for__should_skip_errors_and_return_the_first_match() {
        let mut receiver =
            Scripted::new([Ok(("1", 10)), Err("down"), Ok(("3", 12)), Ok(("4", 13))])
                .view()
                .subscribe(INTERVAL)
                .await;

        let observed = wait_for(&mut receiver, Duration::from_secs(1), |value| *value > 2)
            .await
            .unwrap();

        assert_eq!((observed.result, observed.block_height), (3, 12));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for__should_time_out() {
        let mut receiver = Scripted::new([Ok(("1", 10))])
            .view()
            .subscribe(INTERVAL)
            .await;
        let timeout = Duration::from_millis(50);

        let err = wait_for(&mut receiver, timeout, |value| *value > 1)
            .await
            .unwrap_err();

        assert_eq!(err, WaitError::TimedOut(timeout));
    }
}
