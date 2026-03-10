use crate::errors::ChainGatewayError;
use crate::types::RawObservedState;
use near_account_id::AccountId;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::traits::ViewRaw;

pub(crate) struct MonitoringTask {
    _task_handle: JoinHandle<()>,
    cancel_token: CancellationToken,
    pub last_observed: tokio::sync::watch::Receiver<Result<RawObservedState, ChainGatewayError>>,
}

impl Drop for MonitoringTask {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Spawns a monitoring task with tokio.
/// Cancels the spawned task when dropped.
/// Note: this function returns only after the NEAR indexer has fully synced.
pub(crate) async fn make_monitoring_task<V>(
    viewer: V,
    contract_id: AccountId,
    method_name: &str,
    args: Vec<u8>,
) -> MonitoringTask
where
    V: ViewRaw,
{
    let observed_state = viewer.view_raw(&contract_id, method_name, &args).await;

    let (sender, last_observed) = tokio::sync::watch::channel(observed_state.clone());

    let cancel_token = CancellationToken::new();
    let _task_handle = tokio::spawn(monitor(
        viewer,
        contract_id,
        method_name.to_string(),
        args,
        sender,
        cancel_token.clone(),
    ));

    MonitoringTask {
        _task_handle,
        cancel_token,
        last_observed,
    }
}

pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(200);

async fn monitor<V: ViewRaw>(
    viewer: V,
    contract_id: AccountId,
    method_name: String,
    args: Vec<u8>,
    sender: tokio::sync::watch::Sender<Result<RawObservedState, ChainGatewayError>>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    // consume the first tick
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(
                    contract_id = ?contract_id,
                    method_name = ?method_name,
                    "contract monitoring task cancelled"
                );
                break;
            }
            _ = ticker.tick() => {
                let val = viewer
                    .view_raw(&contract_id, &method_name, &args)
                    .await;

                if sender.send_if_modified(|existing| modify(existing, val)) {
                    tracing::debug!(
                        contract_id = ?contract_id,
                        method_name = ?method_name,
                        "updated value"
                    );
                }
            }
        }
    }
}

/// Conditionally modifies `to_modify` in place and returns a bool indicating if it was modified.
/// `to_modify` is modified if and only if one of the following holds:
///     - `to_modify` is Ok(_) and `update_value` is Err(_) or vice-versa
///     - if `to_modify` and `update_value` are both Ok(RawObservedState) with differing value fields
///     - if `to_modify` and `update_value` are different errors
fn modify(
    to_modify: &mut Result<RawObservedState, ChainGatewayError>,
    update_value: Result<RawObservedState, ChainGatewayError>,
) -> bool {
    let value_changed = match (&to_modify, &update_value) {
        (Ok(prev), Ok(current)) => prev.value != current.value,
        (Err(prev_err), Err(curr_err)) => prev_err.to_string() != curr_err.to_string(),
        _ => true,
    };
    if value_changed {
        *to_modify = update_value;
    }
    value_changed
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        errors::{ChainGatewayError, ChainGatewayOp},
        mock::{Call, MockChainState, MockError},
        state_viewer::monitoring::{POLL_INTERVAL, modify, monitor},
        types::{ObservedState, RawObservedState},
    };
    use rstest::rstest;
    use tokio_util::sync::CancellationToken;

    use super::{MonitoringTask, make_monitoring_task};

    fn expected_call() -> Call {
        Call {
            contract_id: "example.testnet".parse().unwrap(),
            method_name: "example_method".to_string(),
            args: vec![0xAA, 0xBB],
        }
    }

    // unit tests for `modify` function
    #[rstest]
    #[case("same bytes, same height do not update", Ok((0, 0)), Ok((0, 0)), false)]
    #[case("same bytes, different observed_at do not update", Ok((0, 0)), Ok((5, 0)), false)]
    #[case("different bytes, different obseved_at do update", Ok((0, 0)), Ok((1, 1)), true)]
    #[case("different bytes, same obseved_at do update", Ok((0, 0)), Ok((0, 1)), true)]
    #[case("ok -> error does update", Ok((0, 0)), Err(ChainGatewayError::MonitoringClosed), true)]
    #[case("error -> ok does update", Err(ChainGatewayError::MonitoringClosed), Ok((0, 0)), true)]
    #[case(
        "same error string does not update",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::MonitoringClosed),
        false
    )]
    #[case(
        "different error string does update",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::FailureLoadingConfig { msg: "hello".to_string() }),
        true
    )]
    fn test_modify_modifies_correctly(
        #[case] name: &str,
        #[case] existing_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] update_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] expected_changed: bool,
    ) {
        let mut to_modify = existing_spec.map(|(at, b)| RawObservedState {
            observed_at: at.into(),
            value: vec![b],
        });
        let update_value = update_spec.map(|(at, b)| RawObservedState {
            observed_at: at.into(),
            value: vec![b],
        });
        let expected = if expected_changed {
            update_value.clone()
        } else {
            to_modify.clone()
        };

        let changed = modify(&mut to_modify, update_value);

        assert_eq!(changed, expected_changed, "case: {name}");
        match (to_modify, expected) {
            (Err(to_modify), Err(expected)) => {
                assert_eq!(to_modify.to_string(), expected.to_string(), "case: {name}")
            }
            (Ok(to_modify), Ok(expected)) => assert_eq!(to_modify, expected, "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: {a:?}, expected: {b:?}"),
        }
    }

    /// Verifies that the monitor function queries the correct parameters
    #[tokio::test(start_paused = true)]
    async fn test_monitor_queries_correct_params() {
        let init_mock = Ok(ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        });

        let call = expected_call();
        let (viewer, _receiver, _cancel) = setup(call.clone(), init_mock);
        viewer
            .await_next_view_call(POLL_INTERVAL * 2)
            .await
            .unwrap();
        let calls = viewer.view_calls().await;
        assert!(calls.iter().all(|c| c == &call));
        assert!(!calls.is_empty());
    }

    /// Verifies that monitor function emits changes correctly
    #[rstest]
    #[case("same bytes, same height", Ok((0, 0)), Ok((0, 0)), false)]
    #[case("same bytes, different observed_at", Ok((0, 0)), Ok((5, 0)), false)]
    #[case("different bytes, different obseved_at", Ok((0, 0)), Ok((1, 1)), true)]
    #[case("different bytes, same obseved_at", Ok((0, 0)), Ok((0, 1)), true)]
    #[case("ok -> error", Ok((0, 0)), Err(MockError::SyncError), true)]
    #[case("error -> ok", Err(MockError::SyncError), Ok((0, 0)), true)]
    #[case(
        "same error",
        Err(MockError::SyncError),
        Err(MockError::SyncError),
        false
    )]
    #[tokio::test(start_paused = true)]
    async fn test_monitor_notifies_receiver_correctly(
        #[case] name: &str,
        #[case] init_spec: Result<(u64, u8), MockError>,
        #[case] next_spec: Result<(u64, u8), MockError>,
        #[case] expected_changed: bool,
    ) {
        // Given
        let init_mock_response = mock_spec(init_spec.clone());
        let call = expected_call();
        let (viewer, mut receiver, _cancel) = setup(call.clone(), init_mock_response);

        // when: view response changes
        let next_mock_response = mock_spec(next_spec.clone());
        viewer.set_view_response(next_mock_response).await;
        viewer
            .await_next_view_call(POLL_INTERVAL * 2)
            .await
            .unwrap();

        // Then:
        // we expect the receiver to be notified in case of change
        assert_eq!(receiver.has_changed().unwrap(), expected_changed);

        // We expect the value in the receiver to match the expected value
        let found = receiver.borrow_and_update().clone();
        let expected = if expected_changed {
            next_spec
        } else {
            init_spec
        };
        let expected = spec_to_observed(expected, call.clone());
        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }

        let calls = viewer.view_calls().await;
        assert!(calls.iter().all(|c| c == &call), "case: {name}");
    }

    /// Verifies that the monitor function drops the sender when cancelled
    #[tokio::test]
    async fn test_monitor_cancellation_drops_sender() {
        let init_mock = Ok(ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        });
        let (_viewer, mut receiver, cancel) = setup(expected_call(), init_mock);
        cancel.cancel();
        assert!(receiver.changed().await.is_err());
    }

    // make_monitoring_task tests
    #[rstest]
    #[case("initial ok", Ok((0, 0)))]
    #[case("initial err", Err(MockError::SyncError))]
    #[tokio::test(start_paused = true)]
    async fn test_monitoring_task_sets_initial_value_from_first_view(
        #[case] name: &str,
        #[case] init_spec: Result<(u64, u8), MockError>,
    ) {
        let init_mock = mock_spec(init_spec.clone());

        let call = expected_call();
        let (viewer, task) = setup_task(call.clone(), init_mock).await;

        let calls = viewer.view_calls().await;
        assert!(calls.iter().all(|c| c == &call), "case: {name}");
        assert!(!calls.is_empty(), "case: {name}");

        let found = task.last_observed.borrow().clone();

        let expected = spec_to_observed(init_spec, call);
        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }
    }

    // tests that the monitoring task propagates changes correctly
    #[rstest]
    #[case("same bytes, same height", Ok((0, 0)), Ok((0, 0)), false)]
    #[case("same bytes, different observed_at", Ok((0, 0)), Ok((5, 0)), false)]
    #[case("different bytes, different observed_at", Ok((0, 0)), Ok((1, 1)), true)]
    #[case("different bytes, same observed_at", Ok((0, 0)), Ok((0, 1)), true)]
    #[case("ok -> error", Ok((0, 0)), Err(MockError::SyncError), true)]
    #[case("error -> ok", Err(MockError::SyncError), Ok((0, 0)), true)]
    #[case(
        "same error",
        Err(MockError::SyncError),
        Err(MockError::SyncError),
        false
    )]
    #[tokio::test(start_paused = true)]
    async fn test_monitoring_task_change_semantics(
        #[case] name: &str,
        #[case] init_spec: Result<(u64, u8), MockError>,
        #[case] next_spec: Result<(u64, u8), MockError>,
        #[case] expected_changed: bool,
    ) {
        let init_mock = mock_spec(init_spec.clone());
        let next_mock = mock_spec(next_spec.clone());

        let call = expected_call();
        let (viewer, mut task) = setup_task(call.clone(), init_mock).await;

        // Update what the viewer will return on the next poll
        viewer.set_view_response(next_mock).await;

        // Wait for the background monitor loop to actually call view again
        viewer
            .await_next_view_call(POLL_INTERVAL * 2)
            .await
            .unwrap();

        // Now check whether the watch receiver reports a change
        assert_eq!(
            task.last_observed.has_changed().unwrap(),
            expected_changed,
            "case: {name}"
        );

        let found = task.last_observed.borrow_and_update().clone();
        let expected = if expected_changed {
            next_spec
        } else {
            init_spec
        };
        let expected = spec_to_observed(expected, call);
        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }

        let calls = viewer.view_calls().await;
        assert!(calls.iter().all(|c| c == &expected_call()), "case: {name}");
    }

    /// ensurse that the correct parameters are getting queried
    /// note that this test is redundant, since we are testing this in the other tests already
    #[tokio::test(start_paused = true)]
    async fn test_monitoring_task_queries_correct_params() {
        let init_mock = Ok(ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        });

        let call = expected_call();
        let (viewer, _task) = setup_task(call.clone(), init_mock).await;
        viewer
            .await_next_view_call(POLL_INTERVAL * 2)
            .await
            .unwrap();
        let calls = viewer.view_calls().await;
        assert!(calls.iter().all(|c| c == &call));
        assert!(!calls.is_empty());
    }

    #[tokio::test]
    async fn test_monitoring_task_drop_cancels_and_closes_receiver() {
        let init_mock = Ok(ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        });

        let call = expected_call();
        let (_viewer, task) = setup_task(call, init_mock).await;

        // Move receiver out so we can observe closure after dropping the task.
        let mut receiver = task.last_observed.clone();

        // Dropping should cancel the background loop.
        drop(task);

        // Once monitor exits, sender is dropped and changed().await returns Err.
        // Use timeout so the test cannot hang if something is wrong.
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.changed()).await;
        assert!(res.is_ok(), "expected receiver to close after drop");
        assert!(
            res.unwrap().is_err(),
            "expected channel closed (sender dropped)"
        );
    }

    // helper functions

    async fn setup_task(
        call: Call,
        mock_response: Result<RawObservedState, MockError>,
    ) -> (MockChainState, MonitoringTask) {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(mock_response)
            .build();

        let task = make_monitoring_task(
            viewer.clone(),
            call.contract_id.clone(),
            &call.method_name,
            call.args,
        )
        .await;

        (viewer, task)
    }

    fn setup(
        call: Call,
        mock_response: Result<RawObservedState, MockError>,
    ) -> (
        MockChainState,
        tokio::sync::watch::Receiver<Result<RawObservedState, ChainGatewayError>>,
        CancellationToken,
    ) {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(mock_response.clone())
            .build();

        // Initial channel value matches what view_raw would return (wrapping errors)
        let init_channel = mock_response.map_err(|err| ChainGatewayError::ViewClient {
            op: ChainGatewayOp::ViewCall {
                account_id: call.contract_id.to_string(),
                method_name: call.method_name.to_string(),
            },
            source: Arc::new(err),
        });

        let (sender, receiver) = tokio::sync::watch::channel(init_channel);

        let cancel = CancellationToken::new();

        let _handle = tokio::spawn(monitor(
            viewer.clone(),
            call.contract_id.clone(),
            call.method_name,
            call.args,
            sender,
            cancel.clone(),
        ));
        (viewer, receiver, cancel)
    }

    fn mock_spec(spec: Result<(u64, u8), MockError>) -> Result<RawObservedState, MockError> {
        spec.map(|(at, b)| RawObservedState {
            observed_at: at.into(),
            value: vec![b],
        })
    }

    fn spec_to_observed(
        spec: Result<(u64, u8), MockError>,
        call: Call,
    ) -> Result<RawObservedState, ChainGatewayError> {
        match spec {
            Ok((at, b)) => Ok(RawObservedState {
                observed_at: at.into(),
                value: vec![b],
            }),
            Err(err) => Err(ChainGatewayError::ViewClient {
                op: ChainGatewayOp::ViewCall {
                    account_id: call.contract_id.to_string(),
                    method_name: call.method_name,
                },
                source: Arc::new(err),
            }),
        }
    }
}
