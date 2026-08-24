use std::time::Duration;

use near_account_id::AccountId;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{ObservedState, ViewArgs, ViewContract};

/// A watch on the raw bytes of one view method, together with whatever keeps
/// the producer alive.
pub struct Observations<E> {
    receiver: tokio::sync::watch::Receiver<Result<ObservedState, E>>,
    /// Cancels the polling task once the last observer is dropped. `None` for a
    /// backend that publishes its own updates.
    _producer: Option<DropGuard>,
}

impl<E> Observations<E> {
    /// For a backend that publishes updates itself instead of being polled.
    /// Feed `sender` through [`publish_if_changed`] so pushed and polled
    /// subscriptions agree on what counts as a change.
    pub fn pushed(receiver: tokio::sync::watch::Receiver<Result<ObservedState, E>>) -> Self {
        Self {
            receiver,
            _producer: None,
        }
    }

    pub(crate) fn receiver_mut(
        &mut self,
    ) -> &mut tokio::sync::watch::Receiver<Result<ObservedState, E>> {
        &mut self.receiver
    }
}

/// Re-reads `view_args` every `interval`, publishing only genuine changes and
/// stopping once the returned [`Observations`] is dropped.
///
/// Returns after the first read, so a caller has a value without waiting out an
/// interval.
pub async fn poll_observations<V>(
    viewer: V,
    contract_id: AccountId,
    view_args: ViewArgs,
    interval: Duration,
) -> Observations<V::Error>
where
    V: ViewContract + Send + 'static,
    V::Error: Clone + PartialEq + Send + Sync,
{
    let initial = viewer.view_contract(&contract_id, view_args.clone()).await;

    let (sender, receiver) = tokio::sync::watch::channel(initial);

    let cancel = CancellationToken::new();
    tokio::spawn(poll(
        viewer,
        contract_id,
        view_args,
        interval,
        sender,
        cancel.clone(),
    ));

    Observations {
        receiver,
        _producer: Some(cancel.drop_guard()),
    }
}

async fn poll<V>(
    viewer: V,
    contract_id: AccountId,
    view_args: ViewArgs,
    interval: Duration,
    sender: tokio::sync::watch::Sender<Result<ObservedState, V::Error>>,
    cancel: CancellationToken,
) where
    V: ViewContract,
    V::Error: PartialEq,
{
    let mut ticker = tokio::time::interval(interval);
    // consume the first tick
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(
                    contract_id = ?contract_id,
                    method_name = ?view_args.method_name,
                    "contract monitoring task cancelled"
                );
                break;
            }
            _ = ticker.tick() => {
                let observed = viewer
                    .view_contract(&contract_id, view_args.clone())
                    .await;

                if publish_if_changed(&sender, observed) {
                    tracing::debug!(
                        contract_id = ?contract_id,
                        method_name = ?view_args.method_name,
                        "updated value"
                    );
                }
            }
        }
    }
}

/// Publishes `next` only if it differs from the last observation, reporting
/// whether it did. A block-height increase alone is not a change.
///
/// A backend that pushes its own updates should use this rather than
/// [`watch::Sender::send`], so every backend notifies on the same condition.
pub fn publish_if_changed<E>(
    sender: &tokio::sync::watch::Sender<Result<ObservedState, E>>,
    next: Result<ObservedState, E>,
) -> bool
where
    E: PartialEq,
{
    sender.send_if_modified(|current| replace_if_changed(current, next))
}

/// Conditionally modifies `to_modify` in place and returns a bool indicating if it was modified.
/// `to_modify` is modified if and only if one of the following holds:
///     - `to_modify` is Ok(_) and `update_value` is Err(_) or vice-versa
///     - if `to_modify` and `update_value` are both Ok(ObservedState) with differing value fields
///     - if `to_modify` and `update_value` are different errors
fn replace_if_changed<E>(
    to_modify: &mut Result<ObservedState, E>,
    update_value: Result<ObservedState, E>,
) -> bool
where
    E: PartialEq,
{
    let value_changed = match (&to_modify, &update_value) {
        (Ok(prev), Ok(current)) => prev.value != current.value,
        (Err(prev_err), Err(curr_err)) => prev_err != curr_err,
        _ => true,
    };
    if value_changed {
        *to_modify = update_value;
    }
    value_changed
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::time::Duration;

    use rstest::rstest;
    use tokio_util::sync::CancellationToken;

    use super::{Observations, poll, poll_observations, replace_if_changed};
    use crate::test_utils::{RecordingViewer, TestViewError, ViewRequest};
    use crate::types::{ObservedState, ViewArgs};

    const POLL_INTERVAL: Duration = Duration::from_millis(200);

    type Spec = Result<(u64, u8), TestViewError>;

    fn requested() -> ViewRequest {
        ViewRequest {
            contract_id: "example.testnet".parse().unwrap(),
            method_name: "example_method".to_string(),
            args: vec![0xAA, 0xBB],
        }
    }

    fn view_args() -> ViewArgs {
        let request = requested();
        ViewArgs::new(request.method_name, request.args)
    }

    fn observed(spec: Spec) -> Result<ObservedState, TestViewError> {
        spec.map(|(observed_at, byte)| ObservedState {
            observed_at: observed_at.into(),
            value: vec![byte],
        })
    }

    async fn polling(
        initial: Result<ObservedState, TestViewError>,
    ) -> (RecordingViewer<TestViewError>, Observations<TestViewError>) {
        let viewer = RecordingViewer::answering(initial);
        let observations = poll_observations(
            viewer.clone(),
            requested().contract_id,
            view_args(),
            POLL_INTERVAL,
        )
        .await;
        (viewer, observations)
    }

    #[rstest]
    #[case::same_bytes_same_height(Ok((0, 0)), Ok((0, 0)), false)]
    #[case::same_bytes_new_height(Ok((0, 0)), Ok((5, 0)), false)]
    #[case::new_bytes_new_height(Ok((0, 0)), Ok((1, 1)), true)]
    #[case::new_bytes_same_height(Ok((0, 0)), Ok((0, 1)), true)]
    #[case::ok_to_error(Ok((0, 0)), Err(TestViewError::First), true)]
    #[case::error_to_ok(Err(TestViewError::First), Ok((0, 0)), true)]
    #[case::same_error(Err(TestViewError::First), Err(TestViewError::First), false)]
    #[case::different_error(Err(TestViewError::First), Err(TestViewError::Second), true)]
    fn replace_if_changed__should_replace_only_what_differs(
        #[case] existing: Spec,
        #[case] update: Spec,
        #[case] expected_changed: bool,
    ) {
        // Given
        let mut current = observed(existing);
        let update = observed(update);
        let expected = if expected_changed {
            update.clone()
        } else {
            current.clone()
        };

        // When
        let changed = replace_if_changed(&mut current, update);

        // Then
        assert_eq!(changed, expected_changed);
        assert_eq!(current, expected);
    }

    #[tokio::test(start_paused = true)]
    async fn poll__should_query_the_requested_contract_and_method() {
        // Given
        let viewer = RecordingViewer::answering(observed(Ok((0, 0))));
        let cancel = CancellationToken::new();
        let (sender, _receiver) = tokio::sync::watch::channel(observed(Ok((0, 0))));
        tokio::spawn(poll(
            viewer.clone(),
            requested().contract_id,
            view_args(),
            POLL_INTERVAL,
            sender,
            cancel.clone(),
        ));

        // When
        assert!(viewer.await_next_call(POLL_INTERVAL * 2).await);

        // Then
        let calls = viewer.calls();
        assert!(!calls.is_empty());
        assert!(calls.iter().all(|call| call == &requested()));
    }

    #[rstest]
    #[case::same_bytes_same_height(Ok((0, 0)), Ok((0, 0)), false)]
    #[case::same_bytes_new_height(Ok((0, 0)), Ok((5, 0)), false)]
    #[case::new_bytes_new_height(Ok((0, 0)), Ok((1, 1)), true)]
    #[case::new_bytes_same_height(Ok((0, 0)), Ok((0, 1)), true)]
    #[case::ok_to_error(Ok((0, 0)), Err(TestViewError::First), true)]
    #[case::error_to_ok(Err(TestViewError::First), Ok((0, 0)), true)]
    #[case::same_error(Err(TestViewError::First), Err(TestViewError::First), false)]
    #[tokio::test(start_paused = true)]
    async fn poll__should_notify_only_when_the_observation_changes(
        #[case] initial: Spec,
        #[case] next: Spec,
        #[case] expected_changed: bool,
    ) {
        // Given
        let (viewer, mut observations) = polling(observed(initial.clone())).await;

        // When
        viewer.set_response(observed(next.clone()));
        assert!(viewer.await_next_call(POLL_INTERVAL * 2).await);

        // Then
        let receiver = observations.receiver_mut();
        assert_eq!(receiver.has_changed().unwrap(), expected_changed);
        let expected = observed(if expected_changed { next } else { initial });
        assert_eq!(*receiver.borrow_and_update(), expected);
    }

    #[tokio::test(start_paused = true)]
    async fn poll_observations__should_seed_the_first_value_before_any_tick() {
        // Given
        let initial = observed(Ok((7, 3)));

        // When
        let (viewer, mut observations) = polling(initial.clone()).await;

        // Then
        assert_eq!(*observations.receiver_mut().borrow(), initial);
        assert_eq!(viewer.calls(), vec![requested()]);
    }

    #[tokio::test(start_paused = true)]
    async fn poll_observations__should_seed_an_initial_failure() {
        // Given
        let initial = observed(Err(TestViewError::First));

        // When
        let (_viewer, mut observations) = polling(initial.clone()).await;

        // Then
        assert_eq!(*observations.receiver_mut().borrow(), initial);
    }

    #[tokio::test]
    async fn poll__should_close_the_channel_when_cancelled() {
        // Given
        let viewer = RecordingViewer::answering(observed(Ok((0, 0))));
        let cancel = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::watch::channel(observed(Ok((0, 0))));
        tokio::spawn(poll(
            viewer,
            requested().contract_id,
            view_args(),
            POLL_INTERVAL,
            sender,
            cancel.clone(),
        ));

        // When
        cancel.cancel();

        // Then
        assert!(receiver.changed().await.is_err());
    }

    /// Dropping [`Observations`] must stop the polling task, which closes the
    /// channel every remaining observer is watching.
    #[tokio::test]
    async fn observations__should_stop_polling_when_dropped() {
        // Given
        let (_viewer, mut observations) = polling(observed(Ok((0, 0)))).await;
        let mut receiver = observations.receiver_mut().clone();

        // When
        drop(observations);

        // Then
        let closed = tokio::time::timeout(Duration::from_secs(2), receiver.changed())
            .await
            .expect("the channel should close rather than hang");
        assert!(closed.is_err(), "the sender should have been dropped");
    }
}
