use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{BlockHeight, ViewOutput};
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::viewer_trait::ContractViewer;

#[async_trait]
pub trait ContractStateStream<Res> {
    /// Returns the last value observed on chain and the block height at which it last changed.
    fn latest(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError>;
    /// Waits until the observed value changes.
    async fn changed(&mut self) -> Result<(), ChainGatewayError>;

    /// Waits for the next state change and returns the new value.
    async fn next(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError>
    where
        Self: Send,
    {
        self.changed().await?;
        self.latest()
    }
}

pub(crate) struct ContractMethodSubscription<Res> {
    _task_handle: JoinHandle<()>,
    cancel_token: CancellationToken,
    cached: Result<(BlockHeight, Res), ChainGatewayError>,
    last_observed: tokio::sync::watch::Receiver<Result<ObservedState, ChainGatewayError>>,
}

#[async_trait]
impl<Res> ContractStateStream<Res> for ContractMethodSubscription<Res>
where
    Res: DeserializeOwned + Send + Clone,
{
    async fn changed(&mut self) -> Result<(), ChainGatewayError> {
        self.last_observed
            .changed()
            .await
            .map_err(|_| ChainGatewayError::MonitoringClosed)?;
        Ok(())
    }

    fn latest(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError> {
        let observed_or_error = self.last_observed.borrow_and_update().clone();

        let wrapped = match observed_or_error {
            Ok(value) => match serde_json::from_slice::<Res>(&value.value) {
                Ok(res) => Ok((value.last_changed_height, res)),
                Err(err) => Err(ChainGatewayError::Deserialization {
                    source: Arc::new(err),
                }),
            },
            Err(err) => Err(err),
        };

        self.cached = wrapped;
        self.cached.clone()
    }
}

impl<Res> Drop for ContractMethodSubscription<Res> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<Res> ContractMethodSubscription<Res>
where
    Res: DeserializeOwned,
{
    pub(super) async fn new_internal<V: ContractViewer>(
        viewer: V,
        contract_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Self {
        let val = viewer
            .view_raw(&contract_id, method_name, &args)
            .await;
        let observed_state: Result<ObservedState, ChainGatewayError> = val.map(|val| val.into());
        let (sender, last_observed) = tokio::sync::watch::channel(observed_state.clone());
        let cached: Result<(BlockHeight, Res), ChainGatewayError> =
            observed_state.and_then(|value| {
                let deser_value = serde_json::from_slice::<Res>(&value.value).map_err(|err| {
                    ChainGatewayError::Deserialization {
                        source: Arc::new(err),
                    }
                })?;
                Ok((value.last_changed_height, deser_value))
            });

        let cancel_token = CancellationToken::new();
        let _task_handle = tokio::spawn(monitor(
            viewer,
            contract_id,
            method_name.to_string(),
            args,
            sender,
            cancel_token.clone(),
        ));

        Self {
            _task_handle,
            cancel_token,
            cached,
            last_observed,
        }
    }

    pub(super) async fn new<Arg: Serialize, V: ContractViewer>(
        viewer: V,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<Self, ChainGatewayError> {
        tracing::debug!(contract_id=?contract_id, method_name=?method_name, "setting up snapshot");
        let args: Vec<u8> = serde_json::to_string(args)
            .map_err(|err| ChainGatewayError::Serialization {
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })?
            .into_bytes();
        Ok(Self::new_internal(viewer, contract_id, method_name, args).await)
    }
}

#[derive(Clone)]
struct ObservedState {
    pub last_changed_height: BlockHeight,
    pub value: Vec<u8>,
}

impl From<ViewOutput> for ObservedState {
    fn from(value: ViewOutput) -> Self {
        Self {
            last_changed_height: value.block_height,
            value: value.value,
        }
    }
}

fn modify(
    existing: &mut Result<ObservedState, ChainGatewayError>,
    new: Result<ViewOutput, ChainGatewayError>,
) -> bool {
    let value_changed = match (&existing, &new) {
        (Ok(prev_res), Ok(curr_res)) => prev_res.value != curr_res.value,
        (Err(prev_err), Err(curr_err)) => prev_err.to_string() != curr_err.to_string(),
        _ => true,
    };
    if value_changed {
        *existing = new.map(|value| ObservedState {
            last_changed_height: value.block_height,
            value: value.value,
        });
    }
    value_changed
}

async fn monitor<V: ContractViewer>(
    viewer: V,
    contract_id: AccountId,
    method_name: String,
    args: Vec<u8>,
    sender: tokio::sync::watch::Sender<Result<ObservedState, ChainGatewayError>>,
    cancel: CancellationToken,
) {
    const POLL_INTERVAL: Duration = Duration::from_millis(200);

    let mut ticker = tokio::time::interval(POLL_INTERVAL);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[derive(Clone)]
    struct FakeViewer {
        response: Arc<RwLock<Result<ViewOutput, ChainGatewayError>>>,
    }

    #[async_trait]
    impl ContractViewer for FakeViewer {
        async fn view_raw(
            &self,
            _contract_id: &AccountId,
            _method_name: &str,
            _args: &[u8],
        ) -> Result<ViewOutput, ChainGatewayError> {
            self.response.read().await.clone()
        }
    }

    fn make_view_output(value: &str, height: u64) -> ViewOutput {
        ViewOutput {
            block_height: BlockHeight::from(height),
            value: serde_json::to_vec(value).unwrap(),
        }
    }

    fn make_fake_viewer(
        response: Result<ViewOutput, ChainGatewayError>,
    ) -> (FakeViewer, Arc<RwLock<Result<ViewOutput, ChainGatewayError>>>) {
        let response = Arc::new(RwLock::new(response));
        let viewer = FakeViewer {
            response: response.clone(),
        };
        (viewer, response)
    }

    #[tokio::test]
    async fn initial_latest_returns_correct_value() {
        let (viewer, _) = make_fake_viewer(Ok(make_view_output("hello", 1)));

        let mut sub = ContractMethodSubscription::<String>::new_internal(
            viewer,
            "test.near".parse().unwrap(),
            "state",
            b"{}".to_vec(),
        )
        .await;

        let (height, value) = sub.latest().unwrap();
        assert_eq!(value, "hello");
        assert_eq!(u64::from(height), 1);
    }

    #[tokio::test]
    async fn latest_returns_new_value_after_changed() {
        let (viewer, response) = make_fake_viewer(Ok(make_view_output("initial", 1)));

        let mut sub = ContractMethodSubscription::<String>::new_internal(
            viewer,
            "test.near".parse().unwrap(),
            "state",
            b"{}".to_vec(),
        )
        .await;

        assert_eq!(sub.latest().unwrap().1, "initial");

        // Simulate contract state change
        *response.write().await = Ok(make_view_output("updated", 2));

        // The monitor task polls every 200ms — wait for it to detect the change
        sub.changed().await.unwrap();

        // CRITICAL ASSERTION: must return "updated", not stale "initial"
        let (height, value) = sub.latest().unwrap();
        assert_eq!(value, "updated");
        assert_eq!(u64::from(height), 2);
    }

    #[tokio::test]
    async fn error_to_ok_transition_propagated() {
        let initial_err = ChainGatewayError::ViewClient {
            op: ChainGatewayOp::ViewCall {
                account_id: "test.near".to_string(),
                method_name: "state".to_string(),
            },
            source: Arc::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "code does not exist",
            )),
        };
        let (viewer, response) = make_fake_viewer(Err(initial_err));

        let mut sub = ContractMethodSubscription::<String>::new_internal(
            viewer,
            "test.near".parse().unwrap(),
            "state",
            b"{}".to_vec(),
        )
        .await;

        assert!(sub.latest().is_err());

        // Transition to success
        *response.write().await = Ok(make_view_output("recovered", 5));

        sub.changed().await.unwrap();

        let (height, value) = sub.latest().unwrap();
        assert_eq!(value, "recovered");
        assert_eq!(u64::from(height), 5);
    }

    #[tokio::test]
    async fn ok_to_error_transition_propagated() {
        let (viewer, response) = make_fake_viewer(Ok(make_view_output("good", 1)));

        let mut sub = ContractMethodSubscription::<String>::new_internal(
            viewer,
            "test.near".parse().unwrap(),
            "state",
            b"{}".to_vec(),
        )
        .await;

        assert_eq!(sub.latest().unwrap().1, "good");

        // Transition to error
        *response.write().await = Err(ChainGatewayError::ViewClient {
            op: ChainGatewayOp::ViewCall {
                account_id: "test.near".to_string(),
                method_name: "state".to_string(),
            },
            source: Arc::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "node offline",
            )),
        });

        sub.changed().await.unwrap();

        assert!(sub.latest().is_err());
    }

    #[tokio::test]
    async fn same_value_does_not_trigger_changed() {
        let (viewer, _response) = make_fake_viewer(Ok(make_view_output("stable", 1)));

        let mut sub = ContractMethodSubscription::<String>::new_internal(
            viewer,
            "test.near".parse().unwrap(),
            "state",
            b"{}".to_vec(),
        )
        .await;

        assert_eq!(sub.latest().unwrap().1, "stable");

        // The monitor polls with the same value, so changed() should NOT fire.
        // We use a timeout to verify it doesn't.
        let result = tokio::time::timeout(Duration::from_millis(500), sub.changed()).await;
        assert!(result.is_err(), "changed() should have timed out");
    }

    #[tokio::test]
    async fn changed_returns_err_on_drop() {
        let (viewer, _response) = make_fake_viewer(Ok(make_view_output("value", 1)));

        let mut sub = ContractMethodSubscription::<String>::new_internal(
            viewer,
            "test.near".parse().unwrap(),
            "state",
            b"{}".to_vec(),
        )
        .await;

        // Cancel the monitor by dropping the internal cancel token
        // We simulate dropping by cancelling directly
        sub.cancel_token.cancel();

        // Wait for the sender to be dropped (monitor task exits)
        // The watch channel will close
        let result = sub.changed().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ChainGatewayError::MonitoringClosed => {}
            other => panic!("expected MonitoringClosed, got: {:?}", other),
        }
    }

    // Unit tests for the `modify` function

    #[test]
    fn modify_same_ok_no_change() {
        let mut existing: Result<ObservedState, ChainGatewayError> =
            Ok(make_view_output("same", 1).into());
        let new = Ok(make_view_output("same", 2)); // same value, different height
        assert!(!modify(&mut existing, new));
    }

    #[test]
    fn modify_different_ok_changes() {
        let mut existing: Result<ObservedState, ChainGatewayError> =
            Ok(make_view_output("old", 1).into());
        let new = Ok(make_view_output("new", 2));
        assert!(modify(&mut existing, new));
        let state = existing.unwrap();
        assert_eq!(state.value, serde_json::to_vec("new").unwrap());
        assert_eq!(u64::from(state.last_changed_height), 2);
    }

    #[test]
    fn modify_same_err_no_change() {
        let err1 = ChainGatewayError::MonitoringClosed;
        let err2 = ChainGatewayError::MonitoringClosed;
        let mut existing: Result<ObservedState, ChainGatewayError> = Err(err1);
        let new: Result<ViewOutput, ChainGatewayError> = Err(err2);
        assert!(!modify(&mut existing, new));
    }

    #[test]
    fn modify_err_to_ok_changes() {
        let mut existing: Result<ObservedState, ChainGatewayError> =
            Err(ChainGatewayError::MonitoringClosed);
        let new = Ok(make_view_output("recovered", 3));
        assert!(modify(&mut existing, new));
        existing.unwrap();
    }
}
