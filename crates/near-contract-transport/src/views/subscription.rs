use crate::{ObservedState, TransportError, WatchContractState, views::monitoring::MonitoringTask};

impl<T, ViewError> WatchContractState<T, ViewError> for MonitoringTask<T, ViewError>
where
    T: Clone + Send + Sync,
    ViewError: Clone + Send + Sync,
{
    /// The initial observation counts as already seen: this future completes only if a new value
    /// is seen.
    async fn changed(&mut self) -> Result<(), TransportError<ViewError>> {
        self.last_observed
            .changed()
            .await
            .map_err(|_| TransportError::MonitoringClosed)?;
        self.update_cache();
        Ok(())
    }

    fn latest(&mut self) -> Result<ObservedState<T>, TransportError<ViewError>> {
        if self
            .last_observed
            .has_changed()
            .map_err(|_| TransportError::MonitoringClosed)?
        {
            self.update_cache();
        }
        self.cached.clone()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use assert_matches::assert_matches;
    use near_account_id::AccountId;

    use crate::{
        HasPollInterval, ObservedState, TransportError, ViewArgs, WatchContractState,
        mock::{MockViewContract, MockViewError},
        views::{monitoring::MonitoringTask, view_call::ViewCall},
    };
    use std::time::Duration;

    fn contract_id() -> AccountId {
        "test.testnet".parse().unwrap()
    }
    fn view_args() -> ViewArgs {
        ViewArgs::no_args("get_value")
    }
    #[tokio::test]
    async fn subscription__should_deserialize_the_initial_value() {
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 42.into(),
            value: serde_json::to_vec(&"hello").unwrap(),
        }));
        let view_call = ViewCall::json(viewer, contract_id(), view_args());
        let mut sub = MonitoringTask::<String, _>::new(view_call).await;

        let state = sub.latest().unwrap();
        assert_eq!(state.value, "hello");
        assert_eq!(state.observed_at, 42.into());
    }

    #[tokio::test]
    async fn subscription__should_propagate_a_view_error() {
        let account_id: AccountId = "test.testnet".parse().unwrap();
        let method_name = "get_value".to_string();
        let viewer = MockViewContract::new(Err(MockViewError("view failed")));

        let call = ViewCall::json(viewer, account_id.clone(), ViewArgs::no_args(&method_name));
        let mut sub = MonitoringTask::<String, _>::new(call).await;

        assert_eq!(
            sub.latest().unwrap_err(),
            TransportError::View(MockViewError("view failed"))
        );
    }

    #[tokio::test]
    async fn subscription__should_return_a_deserialization_error_on_bad_json() {
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 1.into(),
            value: b"not json".to_vec(),
        }));

        let call = ViewCall::json(viewer, contract_id(), view_args());
        let mut sub = MonitoringTask::<String, _>::new(call).await;

        let err = sub.latest().unwrap_err();
        assert_matches!(err, TransportError::Deserialization(_));
    }

    #[tokio::test(start_paused = true)]
    async fn subscription_latest__should_update_on_value_change() {
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 1.into(),
            value: serde_json::to_vec(&"initial").unwrap(),
        }));
        let call = ViewCall::json(viewer.clone(), contract_id(), view_args());
        let mut sub = MonitoringTask::<String, _>::new(call).await;
        assert_eq!(sub.latest().unwrap().value, "initial");

        viewer.set_response(Ok(ObservedState {
            observed_at: 2.into(),
            value: serde_json::to_vec(&"updated").unwrap(),
        }));

        // Advance past poll interval
        tokio::time::sleep(2 * Duration::from(viewer.poll_interval())).await;

        let found = sub.latest().unwrap();
        assert_eq!(found.value, "updated");
        assert_eq!(found.observed_at, 2.into());

        let cached = sub.cached.unwrap();
        assert_eq!(cached.value, "updated");
        assert_eq!(cached.observed_at, 2.into());
    }

    #[tokio::test(start_paused = true)]
    async fn subscription_changed__should_resolve_and_update_the_cache() {
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 1.into(),
            value: serde_json::to_vec(&"before").unwrap(),
        }));

        let call = ViewCall::json(viewer.clone(), contract_id(), view_args());
        let mut sub = MonitoringTask::<String, _>::new(call).await;
        assert_eq!(sub.latest().unwrap().value, "before");

        viewer.set_response(Ok(ObservedState {
            observed_at: 5.into(),
            value: serde_json::to_vec(&"after").unwrap(),
        }));

        tokio::time::timeout(Duration::from_secs(2), sub.changed())
            .await
            .expect("changed() should resolve")
            .unwrap();

        let found = sub.cached.unwrap();
        assert_eq!(found.value, "after");
        assert_eq!(found.observed_at, 5.into());
    }
}
