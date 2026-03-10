use super::monitoring::{MonitoringTask, make_monitoring_task};
use super::traits::{ContractStateStream, ContractViewer};
use crate::errors::ChainGatewayError;
use crate::types::ObservedState;
use near_account_id::AccountId;
use serde::de::DeserializeOwned;

/// Holds  a Monitoring task and the latest cached value.
/// This is useful such that we don't unnecessarily deserialze the same state multiple times.
pub(crate) struct ContractMethodSubscription<Res> {
    inner: MonitoringTask,
    cached: Result<ObservedState<Res>, ChainGatewayError>,
}

impl<Res> ContractMethodSubscription<Res>
where
    Res: DeserializeOwned,
{
    fn update_cache(&mut self) {
        let observed = self.inner.last_observed.borrow_and_update().clone();
        self.cached = observed.and_then(|value| value.deserialize());
    }
}

impl<Res> ContractStateStream<Res> for ContractMethodSubscription<Res>
where
    Res: DeserializeOwned + Send + Clone,
{
    async fn changed(&mut self) -> Result<(), ChainGatewayError> {
        self.inner
            .last_observed
            .changed()
            .await
            .map_err(|_| ChainGatewayError::MonitoringClosed)?;
        self.update_cache();
        Ok(())
    }

    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError> {
        if self
            .inner
            .last_observed
            .has_changed()
            .map_err(|_| ChainGatewayError::MonitoringClosed)?
        {
            self.update_cache();
        }
        self.cached.clone()
    }
}

impl<Res> ContractMethodSubscription<Res>
where
    Res: DeserializeOwned,
{
    pub(super) async fn new<V: ContractViewer>(
        viewer: V,
        contract_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Self {
        let mut task = make_monitoring_task(viewer, contract_id, method_name, args).await;
        let cached: Result<ObservedState<Res>, ChainGatewayError> = task
            .last_observed
            .borrow_and_update()
            .clone()
            .and_then(|value| value.deserialize());
        Self {
            inner: task,
            cached,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ContractMethodSubscription;
    use crate::errors::ChainGatewayError;
    use crate::mock::{MockChainState, MockError};
    use crate::state_viewer::ContractStateStream;
    use crate::types::RawObservedState;
    use std::time::Duration;

    #[tokio::test]
    async fn test_subscription_constructor_deserializes_initial_value() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 42.into(),
                value: serde_json::to_vec(&"hello").unwrap(),
            }))
            .build();

        let mut sub = ContractMethodSubscription::<String>::new(
            viewer,
            "test.testnet".parse().unwrap(),
            "get_value",
            b"{}".to_vec(),
        )
        .await;

        let state = sub.latest().unwrap();
        assert_eq!(state.value, "hello");
        assert_eq!(state.observed_at, 42.into());
    }

    #[tokio::test]
    async fn test_subscription_constructor_propagates_view_error() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Err(MockError::RpcError))
            .build();

        let mut sub = ContractMethodSubscription::<String>::new(
            viewer,
            "test.testnet".parse().unwrap(),
            "get_value",
            b"{}".to_vec(),
        )
        .await;

        assert!(matches!(
            sub.latest().unwrap_err(),
            ChainGatewayError::ViewClient { .. }
        ));
    }

    #[tokio::test]
    async fn test_subscription_constructor_returns_deserialization_error_on_bad_json() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 1.into(),
                value: b"not json".to_vec(),
            }))
            .build();

        let mut sub = ContractMethodSubscription::<String>::new(
            viewer,
            "test.testnet".parse().unwrap(),
            "get_value",
            b"{}".to_vec(),
        )
        .await;

        assert!(matches!(
            sub.latest().unwrap_err(),
            ChainGatewayError::Deserialization { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscription_latest_updates_on_value_change() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 1.into(),
                value: serde_json::to_vec(&"initial").unwrap(),
            }))
            .build();

        let mut sub = ContractMethodSubscription::<String>::new(
            viewer.clone(),
            "test.testnet".parse().unwrap(),
            "get_value",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(sub.latest().unwrap().value, "initial");

        viewer
            .set_view_response(Ok(RawObservedState {
                observed_at: 2.into(),
                value: serde_json::to_vec(&"updated").unwrap(),
            }))
            .await;

        // Advance past poll interval
        tokio::time::sleep(Duration::from_millis(300)).await;

        let found = sub.latest().unwrap();
        assert_eq!(found.value, "updated");
        assert_eq!(found.observed_at, 2.into());
        let found = sub.cached.unwrap();
        assert_eq!(found.value, "updated");
        assert_eq!(found.observed_at, 2.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscription_changed_resolves_and_updates_cache() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 1.into(),
                value: serde_json::to_vec(&"before").unwrap(),
            }))
            .build();

        let mut sub = ContractMethodSubscription::<String>::new(
            viewer.clone(),
            "test.testnet".parse().unwrap(),
            "get_value",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(sub.latest().unwrap().value, "before");

        viewer
            .set_view_response(Ok(RawObservedState {
                observed_at: 5.into(),
                value: serde_json::to_vec(&"after").unwrap(),
            }))
            .await;

        tokio::time::timeout(Duration::from_secs(2), sub.changed())
            .await
            .expect("changed() should resolve")
            .unwrap();

        let found = sub.cached.unwrap();
        assert_eq!(found.value, "after");
        assert_eq!(found.observed_at, 5.into());
    }
}
