use crate::errors::ChainGatewayError;
use crate::near_internals_wrapper::ViewOutput;
use near_account_id::AccountId;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::subscription_trait::ObservedChainState;
use super::viewer_trait::ContractViewer;

pub(crate) struct MonitoringTask {
    _task_handle: JoinHandle<()>,
    cancel_token: CancellationToken,
    pub last_observed: tokio::sync::watch::Receiver<Result<ObservedChainState, ChainGatewayError>>,
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
    let val = viewer.view_raw(&contract_id, method_name, &args).await;
    let observed_state: Result<ObservedChainState, ChainGatewayError> = val.map(Into::into);

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

pub(crate) async fn monitor<V: ContractViewer>(
    viewer: V,
    contract_id: AccountId,
    method_name: String,
    args: Vec<u8>,
    sender: tokio::sync::watch::Sender<Result<ObservedChainState, ChainGatewayError>>,
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

/// conditionally modifies `to_modify` in place and returns a bool indicating if it was modified
/// `to_modify` is modified if and only if one of the following holds:
///     - `to_modify` is Ok(_) and `update_value` is Err(_) or vice-versa
///     - if `to_modify` and `update_value` are both Ok(ObservedChainState) with differing value fields
///     - if `to_modify` and `update_value` are different errors
fn modify(
    to_modify: &mut Result<ObservedChainState, ChainGatewayError>,
    update_value: Result<ViewOutput, ChainGatewayError>,
) -> bool {
    let value_changed = match (&to_modify, &update_value) {
        (
            Ok(ObservedChainState {
                value: prev_value, ..
            }),
            Ok(ViewOutput {
                value: current_value,
                ..
            }),
        ) => prev_value != current_value,
        (Err(prev_err), Err(curr_err)) => prev_err.to_string() != curr_err.to_string(),
        _ => true,
    };
    if value_changed {
        *to_modify = update_value.map(|value| ObservedChainState {
            last_changed: value.observed_at,
            value: value.value,
        });
    }
    value_changed
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::ChainGatewayError,
        near_internals_wrapper::ViewOutput,
        state_viewer::{
            monitoring::{POLL_INTERVAL, modify, monitor},
            subscription_trait::ObservedChainState,
            viewer_trait::ContractViewer,
        },
    };
    use async_trait::async_trait;
    use near_account_id::AccountId;
    use rstest::rstest;
    use std::sync::Arc;
    use tokio::sync::Mutex;
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
        let update_value = spec_to_view(update_spec);

        let expected = if expected_changed {
            update_value.clone().map(|val| ObservedChainState {
                last_changed: val.observed_at,
                value: val.value,
            })
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
        let (viewer, mut receiver, _cancel) = setup(spec_to_view(init_spec.clone()));

        viewer.set_val(spec_to_view(next_spec.clone())).await;

        viewer.await_next_call().await;
        assert_eq!(receiver.has_changed().unwrap(), expected_changed);
        let found = receiver.borrow_and_update().clone();

        let expected = if expected_changed {
            spec_to_observed(next_spec)
        } else {
            spec_to_observed(init_spec)
        };
        match (found, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e, "case: {name}"),
            (Err(g), Err(e)) => assert_eq!(g.to_string(), e.to_string(), "case: {name}"),
            (a, b) => panic!("case: {name}, mismatch: got {a:?}, expected {b:?}"),
        }

        assert_eq!(viewer.num_unexpected_calls().await, 0, "case: {name}");
    }

    #[tokio::test]
    async fn test_monitor_queries_correct_params() {
        let init_value = ViewOutput {
            observed_at: 0.into(),
            value: vec![0],
        };

        let (viewer, _receiver, _cancel) = setup(Ok(init_value.clone()));
        // wait for the first call
        viewer.await_next_call().await;
        // Assert that no incorrect params were queried
        assert_eq!(viewer.num_unexpected_calls().await, 0);
        assert!(viewer.num_expected_calls().await > 0);
    }

    #[tokio::test]
    async fn test_monitor_cancellation_drops_sender() {
        let init_value = ViewOutput {
            observed_at: 0.into(),
            value: vec![0],
        };
        let (_viewer, mut receiver, cancel) = setup(Ok(init_value.clone()));
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
        let init_value = spec_to_view(init_spec.clone());
        let (viewer, task) = setup_task(init_value).await;

        // make_monitoring_task does exactly one view_raw before spawning the loop
        assert_eq!(viewer.num_unexpected_calls().await, 0, "case: {name}");
        assert!(viewer.num_expected_calls().await >= 1, "case: {name}");

        let found = task.last_observed.borrow().clone();
        let expected = spec_to_observed(init_spec);

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
        let init_value = spec_to_view(init_spec.clone());
        let next_value = spec_to_view(next_spec.clone());

        let (viewer, mut task) = setup_task(init_value).await;

        // Update what the viewer will return on the next poll
        viewer.set_val(next_value).await;

        // Wait for the background monitor loop to actually call view_raw again
        viewer.await_next_call().await;

        // Now check whether the watch receiver reports a change
        assert_eq!(
            task.last_observed.has_changed().unwrap(),
            expected_changed,
            "case: {name}"
        );

        let found = task.last_observed.borrow_and_update().clone();

        let expected = if expected_changed {
            spec_to_observed(next_spec)
        } else {
            spec_to_observed(init_spec)
        };

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
        let init_value = ViewOutput {
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
        let init_value = ViewOutput {
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

    // hepler functions
    async fn setup_task(
        init_value: Result<ViewOutput, ChainGatewayError>,
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
        init_value: Result<ViewOutput, ChainGatewayError>,
    ) -> (
        MockViewer,
        tokio::sync::watch::Receiver<Result<ObservedChainState, ChainGatewayError>>,
        CancellationToken,
    ) {
        let call = Call {
            contract_id: "example.testnet".parse().unwrap(),
            method_name: "example_method".to_string(),
            args: vec![0xAA, 0xBB],
        };
        let viewer = MockViewer::new(call.clone(), init_value.clone());

        let (sender, receiver) = tokio::sync::watch::channel::<
            Result<ObservedChainState, ChainGatewayError>,
        >(init_value.map(|val| val.into()));

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

    fn spec_to_view(
        spec: Result<(u64, u8), ChainGatewayError>,
    ) -> Result<ViewOutput, ChainGatewayError> {
        spec.map(|(at, b)| ViewOutput {
            observed_at: at.into(),
            value: vec![b],
        })
    }
    fn spec_to_observed(
        spec: Result<(u64, u8), ChainGatewayError>,
    ) -> Result<ObservedChainState, ChainGatewayError> {
        spec.map(|(at, b)| ObservedChainState {
            last_changed: at.into(),
            value: vec![b],
        })
    }

    #[derive(Clone)]
    struct MockViewer {
        expected_call: Call,
        inner: Arc<Mutex<MockViewerState>>,
    }

    struct MockViewerState {
        num_expected_calls: usize,
        num_unexpected_calls: usize,
        current_value: Result<ViewOutput, ChainGatewayError>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Call {
        contract_id: AccountId,
        method_name: String,
        args: Vec<u8>,
    }

    #[async_trait]
    impl ContractViewer for MockViewer {
        async fn view_raw(
            &self,
            contract_id: &AccountId,
            method_name: &str,
            args: &[u8],
        ) -> Result<ViewOutput, ChainGatewayError> {
            let call = Call {
                contract_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args: args.to_vec(),
            };
            let expected = call == self.expected_call;

            let mut inner = self.inner.lock().await;
            if expected {
                inner.num_expected_calls += 1;
            } else {
                inner.num_unexpected_calls += 1;
            }
            inner.current_value.clone()
        }
    }

    impl MockViewer {
        async fn set_val(&self, value: Result<ViewOutput, ChainGatewayError>) {
            self.inner.lock().await.current_value = value;
        }

        fn new(expected_call: Call, value: Result<ViewOutput, ChainGatewayError>) -> Self {
            Self {
                expected_call,
                inner: Arc::new(Mutex::new(MockViewerState {
                    num_unexpected_calls: 0,
                    num_expected_calls: 0,
                    current_value: value,
                })),
            }
        }
        async fn num_expected_calls(&self) -> usize {
            self.inner.lock().await.num_expected_calls
        }
        async fn num_unexpected_calls(&self) -> usize {
            self.inner.lock().await.num_unexpected_calls
        }
        async fn total_number_calls(&self) -> usize {
            let inner = self.inner.lock().await;
            inner.num_unexpected_calls + inner.num_expected_calls
        }
        async fn await_next_call(&self) {
            let start = self.total_number_calls().await;
            while self.total_number_calls().await == start {
                tokio::time::sleep(POLL_INTERVAL / 2).await
            }
        }
    }
}
