use std::pin::Pin;

use near_account_id::AccountId;

use crate::{
    HasPollInterval, ObservedState, SerializedObservation, TransportError, ViewArgs, ViewContract,
    WatchContractState,
    views::{
        deserialize::{DeserializeAs, Deserializer},
        monitoring::MonitoringTask,
    },
};

pub struct ViewCall<Viewer, T> {
    pub(crate) viewer: Viewer,
    pub(crate) contract_id: AccountId,
    pub(crate) args: ViewArgs,
    pub(crate) deserializer: Deserializer<T>,
}

impl<Viewer, T> ViewCall<Viewer, T> {
    pub fn new<D: DeserializeAs<T>>(
        viewer: Viewer,
        contract_id: AccountId,
        args: ViewArgs,
    ) -> Self {
        Self {
            viewer,
            contract_id,
            args,
            deserializer: D::deserializer(),
        }
    }
}

impl<V, T> IntoFuture for ViewCall<V, T>
where
    V: ViewContract + Send + 'static,
    T: Send + 'static,
{
    type Output = Result<ObservedState<T>, TransportError<V::Error>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.call_and_deserialize())
    }
}

impl<Viewer, T> ViewCall<Viewer, T>
where
    Viewer: ViewContract,
{
    async fn call_and_deserialize(self) -> Result<ObservedState<T>, TransportError<Viewer::Error>> {
        let observed = self
            .viewer
            .view_contract(&self.contract_id, self.args)
            .await;
        deserialize_res(observed, self.deserializer)
    }
}

pub(crate) fn deserialize_res<T, ViewError>(
    raw: Result<SerializedObservation, ViewError>,
    deserializer: Deserializer<T>,
) -> Result<ObservedState<T>, TransportError<ViewError>> {
    let ObservedState { value, observed_at } = raw.map_err(TransportError::View)?;
    let value = deserializer(&value).map_err(TransportError::Deserialization)?;
    Ok(ObservedState { observed_at, value })
}

impl<Viewer, T> ViewCall<Viewer, T>
where
    Viewer: ViewContract + HasPollInterval + Send + 'static,
    T: Clone + Send + Sync,
{
    pub async fn subscribe(self) -> impl WatchContractState<T, Viewer::Error> {
        MonitoringTask::<T, Viewer::Error>::new(self).await
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use assert_matches::assert_matches;
    use near_account_id::AccountId;

    use crate::{
        Borsh, Json, ObservedState, TransportError, ViewArgs,
        mock::{Call, MockViewContract, MockViewError},
        views::view_call::ViewCall,
    };

    fn contract_id() -> AccountId {
        "example.testnet".parse().unwrap()
    }

    #[tokio::test]
    async fn view_call_json__should_return_deserialized_value_and_height() {
        // Given
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 7.into(),
            value: serde_json::to_vec(&"hello").unwrap(),
        }));

        // When
        let observed: ObservedState<String> =
            ViewCall::new::<Json>(viewer, contract_id(), ViewArgs::no_args("get_value"))
                .await
                .unwrap();

        // Then
        assert_eq!(observed.value, "hello");
        assert_eq!(observed.observed_at, 7.into());
    }

    #[tokio::test]
    async fn view_call_json__should_query_requested_contract_and_method() {
        // Given
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 1.into(),
            value: serde_json::to_vec(&"x").unwrap(),
        }));
        let args = ViewArgs::new("get_value".to_string(), vec![0xAA]);

        // When
        let _: ObservedState<String> = ViewCall::new::<Json>(viewer.clone(), contract_id(), args)
            .await
            .unwrap();

        // Then
        assert_eq!(
            viewer.calls(),
            vec![Call {
                contract_id: contract_id(),
                method_name: "get_value".to_string(),
                args: vec![0xAA],
            }]
        );
    }

    #[tokio::test]
    async fn view_call_json__should_propagate_view_error() {
        // Given
        let viewer = MockViewContract::new(Err(MockViewError("view failed")));

        // When
        let err = ViewCall::<_, String>::new::<Json>(
            viewer,
            contract_id(),
            ViewArgs::no_args("get_value"),
        )
        .await
        .unwrap_err();

        // Then
        assert_eq!(err, TransportError::View(MockViewError("view failed")));
    }

    #[tokio::test]
    async fn view_call_json__should_return_deserialization_error_on_invalid_bytes() {
        // Given
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 1.into(),
            value: b"not json".to_vec(),
        }));

        // When
        let err = ViewCall::<_, String>::new::<Json>(
            viewer,
            contract_id(),
            ViewArgs::no_args("get_value"),
        )
        .await
        .unwrap_err();

        // Then
        assert_matches!(err, TransportError::Deserialization(_));
    }

    #[tokio::test]
    async fn view_call_borsh__should_return_deserialized_value_and_height() {
        // Given
        let viewer = MockViewContract::new(Ok(ObservedState {
            observed_at: 3.into(),
            value: borsh::to_vec(&42u64).unwrap(),
        }));

        // When
        let observed: ObservedState<u64> =
            ViewCall::new::<Borsh>(viewer, contract_id(), ViewArgs::no_args("get_value"))
                .await
                .unwrap();

        // Then
        assert_eq!(observed.value, 42);
        assert_eq!(observed.observed_at, 3.into());
    }
}
