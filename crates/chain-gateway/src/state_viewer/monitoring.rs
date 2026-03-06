use crate::errors::ChainGatewayError;
use crate::types::RawObservedState;
use near_account_id::AccountId;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::traits::ContractViewer;

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
    V: ContractViewer,
{
    let observed_state = viewer.view(&contract_id, method_name, &args).await;

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

const POLL_INTERVAL: Duration = Duration::from_millis(200);

async fn monitor<V: ContractViewer>(
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
                tracing::debug!(
                    contract_id = ?contract_id,
                    method_name = ?method_name,
                    "contract monitoring task cancelled"
                );
                break;
            }
            _ = ticker.tick() => {
                let val = viewer
                    .view(&contract_id, &method_name, &args)
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

/// conditionally modifies `to_modify` in place and returns a bool indicating if it was modified
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
    use crate::{
        errors::ChainGatewayError,
        state_viewer::{
            mock_viewer::{Call, MockViewer},
            monitoring::{modify, monitor},
        },
        types::{ObservedState, RawObservedState},
    };
    use rstest::rstest;
    use tokio_util::sync::CancellationToken;

    use super::{MonitoringTask, make_monitoring_task};

    // unit test for `modify` function
    #[rstest]
    #[case("same bytes, same height", Ok((0, 0)), Ok((0, 0)), false)]
    #[case("same bytes, different observed_at", Ok((0, 0)), Ok((5, 0)), false)]
    #[case("different bytes, different obseved_at", Ok((0, 0)), Ok((1, 1)), true)]
    #[case("different bytes, same obseved_at", Ok((0, 0)), Ok((0, 1)), true)]
    #[case("ok -> error", Ok((0, 0)), Err(ChainGatewayError::MonitoringClosed), true)]
    #[case("error -> ok", Err(ChainGatewayError::MonitoringClosed), Ok((0, 0)), true)]
    #[case(
        "same error string",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::MonitoringClosed),
        false
    )]
    #[case(
        "different error string",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::FailureLoadingConfig { msg: "hello".to_string() }),
        true
    )]
    fn test_modify(
        #[case] name: &str,
        #[case] existing_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] update_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] expected_changed: bool,
    ) {
        let mut to_modify = spec_to_observed(existing_spec);
        let update_value = spec_to_observed(update_spec);
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

    // unit tests for monitor function
    #[rstest]
    #[case("same bytes, same height", Ok((0, 0)), Ok((0, 0)), false)]
    #[case("same bytes, different observed_at", Ok((0, 0)), Ok((5, 0)), false)]
    #[case("different bytes, different obseved_at", Ok((0, 0)), Ok((1, 1)), true)]
    #[case("different bytes, same obseved_at", Ok((0, 0)), Ok((0, 1)), true)]
    #[case("ok -> error", Ok((0, 0)), Err(ChainGatewayError::MonitoringClosed), true)]
    #[case("error -> ok", Err(ChainGatewayError::MonitoringClosed), Ok((0, 0)), true)]
    #[case(
        "same error string",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::MonitoringClosed),
        false
    )]
    #[case(
        "different error string",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::FailureLoadingConfig { msg: "hello".to_string() }),
        true
    )]
    #[tokio::test]
    async fn test_monitor_emits_change(
        #[case] name: &str,
        #[case] init_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] next_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] expected_changed: bool,
    ) {
        let init_value = spec_to_observed(init_spec);
        let next_value = spec_to_observed(next_spec);
        let expected = if expected_changed {
            next_value.clone()
        } else {
            init_value.clone()
        };

        let (viewer, mut receiver, _cancel) = setup(init_value);
        viewer.set_val(next_value).await;
        viewer.await_next_call().await;
        assert_eq!(receiver.has_changed().unwrap(), expected_changed);
        let found = receiver.borrow_and_update().clone();

        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }

        assert_eq!(viewer.num_unexpected_calls().await, 0, "case: {name}");
    }

    #[tokio::test]
    async fn test_monitor_queries_correct_params() {
        let init_value = ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        };

        let (viewer, _receiver, _cancel) = setup(Ok(init_value));
        // wait for the first call
        viewer.await_next_call().await;
        // Assert that no incorrect params were queried
        assert_eq!(viewer.num_unexpected_calls().await, 0);
        assert!(viewer.num_expected_calls().await > 0);
    }

    #[tokio::test]
    async fn test_monitor_cancellation_drops_sender() {
        let init_value = ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        };
        let (_viewer, mut receiver, cancel) = setup(Ok(init_value));
        cancel.cancel();
        assert!(receiver.changed().await.is_err());
    }

    // make_monitoring_test
    #[rstest]
    #[case("initial ok", Ok((0, 0)))]
    #[case("initial err", Err(ChainGatewayError::MonitoringClosed))]
    #[tokio::test(start_paused = true)]
    async fn test_monitoring_task_sets_initial_value_from_first_view(
        #[case] name: &str,
        #[case] init_spec: Result<(u64, u8), ChainGatewayError>,
    ) {
        let init_value = spec_to_observed(init_spec);
        let expected = init_value.clone();
        let (viewer, task) = setup_task(init_value).await;

        // make_monitoring_task does exactly one view before spawning the loop
        assert_eq!(viewer.num_unexpected_calls().await, 0, "case: {name}");
        assert!(viewer.num_expected_calls().await >= 1, "case: {name}");

        let found = task.last_observed.borrow().clone();

        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }
    }

    #[rstest]
    #[case("same bytes, same height", Ok((0, 0)), Ok((0, 0)), false)]
    #[case("same bytes, different observed_at", Ok((0, 0)), Ok((5, 0)), false)]
    #[case("different bytes, different observed_at", Ok((0, 0)), Ok((1, 1)), true)]
    #[case("different bytes, same observed_at", Ok((0, 0)), Ok((0, 1)), true)]
    #[case("ok -> error", Ok((0, 0)), Err(ChainGatewayError::MonitoringClosed), true)]
    #[case("error -> ok", Err(ChainGatewayError::MonitoringClosed), Ok((0, 0)), true)]
    #[case(
        "same error string",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::MonitoringClosed),
        false
    )]
    #[case(
        "different error string",
        Err(ChainGatewayError::MonitoringClosed),
        Err(ChainGatewayError::FailureLoadingConfig { msg: "hello".to_string() }),
        true
    )]
    #[tokio::test]
    async fn test_monitoring_task_change_semantics(
        #[case] name: &str,
        #[case] init_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] next_spec: Result<(u64, u8), ChainGatewayError>,
        #[case] expected_changed: bool,
    ) {
        let init_value = spec_to_observed(init_spec);
        let next_value = spec_to_observed(next_spec);

        let expected = if expected_changed {
            next_value.clone()
        } else {
            init_value.clone()
        };

        let (viewer, mut task) = setup_task(init_value).await;

        // Update what the viewer will return on the next poll
        viewer.set_val(next_value).await;

        // Wait for the background monitor loop to actually call view again
        viewer.await_next_call().await;

        // Now check whether the watch receiver reports a change
        assert_eq!(
            task.last_observed.has_changed().unwrap(),
            expected_changed,
            "case: {name}"
        );

        let found = task.last_observed.borrow_and_update().clone();

        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }

        assert_eq!(viewer.num_unexpected_calls().await, 0, "case: {name}");
    }

    // this test is redundant, because we test it in the other tests too. But it's useful to keep
    // as an isolated unit test
    #[tokio::test]
    async fn test_monitoring_task_queries_correct_params() {
        let init_value = ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        };

        let (viewer, _task) = setup_task(Ok(init_value)).await;
        viewer.await_next_call().await;
        // It must have called at least once (initial view)
        assert_eq!(viewer.num_unexpected_calls().await, 0);
        assert!(viewer.num_expected_calls().await > 0);
    }

    #[tokio::test]
    async fn test_monitoring_task_drop_cancels_and_closes_receiver() {
        let init_value = ObservedState {
            observed_at: 0.into(),
            value: vec![0],
        };

        let (_viewer, task) = setup_task(Ok(init_value)).await;

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
        init_value: Result<RawObservedState, ChainGatewayError>,
    ) -> (MockViewer, MonitoringTask) {
        let call = Call {
            contract_id: "example.testnet".parse().unwrap(),
            method_name: "example_method".to_string(),
            args: vec![0xAA, 0xBB],
        };
        let viewer = MockViewer::new(call.clone(), init_value);

        let task = make_monitoring_task(
            viewer.clone(),
            call.contract_id.clone(),
            &call.method_name,
            call.args.clone(),
        )
        .await;

        (viewer, task)
    }

    fn setup(
        init_value: Result<RawObservedState, ChainGatewayError>,
    ) -> (
        MockViewer,
        tokio::sync::watch::Receiver<Result<RawObservedState, ChainGatewayError>>,
        CancellationToken,
    ) {
        let call = Call {
            contract_id: "example.testnet".parse().unwrap(),
            method_name: "example_method".to_string(),
            args: vec![0xAA, 0xBB],
        };
        let viewer = MockViewer::new(call.clone(), init_value.clone());

        let (sender, receiver) = tokio::sync::watch::channel(init_value);

        let cancel = CancellationToken::new();

        let _handle = tokio::spawn(monitor(
            viewer.clone(),
            call.contract_id.clone(),
            call.method_name,
            call.args.clone(),
            sender,
            cancel.clone(),
        ));
        (viewer, receiver, cancel)
    }

    fn spec_to_observed(
        spec: Result<(u64, u8), ChainGatewayError>,
    ) -> Result<RawObservedState, ChainGatewayError> {
        spec.map(|(at, b)| RawObservedState {
            observed_at: at.into(),
            value: vec![b],
        })
    }
}
