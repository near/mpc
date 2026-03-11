use std::future::Future;
use std::sync::Arc;

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::primitives::{IsSyncing, SubmitViewFunctionQuery};
use crate::types::ObservedState;
use near_account_id::AccountId;
use serde::{Serialize, de::DeserializeOwned};

use super::subscription::ContractMethodSubscription;

/// All other viewer traits are derived from this one
pub trait ViewContract: IsSyncing + SubmitViewFunctionQuery {
    // waits until self is synced and then queries the view function
    fn view_raw(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> impl Future<Output = Result<ObservedState, ChainGatewayError>> + Send {
        async move {
            self.wait_for_full_sync().await;
            self.view_function_query(contract_id, method_name, args)
                .await
                .map_err(|err| ChainGatewayError::ViewClient {
                    op: ChainGatewayOp::ViewCall {
                        account_id: contract_id.to_string(),
                        method_name: method_name.to_string(),
                    },
                    source: Arc::new(err),
                })
        }
    }
}

/// Blanket-implemented for all `T: HasViewContract`.
///
/// Provides a subscribe-and-poll interface for observing contract state changes.
/// Polls the view method every 200 ms and emits change notifications only when
/// the returned bytes differ.
///
/// # Example
///
/// ```
/// use chain_gateway::mock::{MockChainState, Call};
/// use chain_gateway::state_viewer::{StreamContractState, SubscribeContractState};
/// use chain_gateway::types::ObservedState;
///
/// #[tokio::main]
/// async fn main() {
///     let viewer = MockChainState::builder()
///         .with_syncing_status(Ok(false))
///         .with_view_function_query_response(Ok(ObservedState {
///             observed_at: 1.into(),
///             value: br#""hello""#.to_vec(),
///         }))
///         .build();
///
///     let mut stream = viewer
///         .subscribe::<String>("contract.near".parse().unwrap(), "get_greeting")
///         .await;
///
///     let state = stream.latest().unwrap();
///     assert_eq!(state.value, "hello");
/// }
/// ```
pub trait SubscribeContractState: ViewContract + Clone {
    /// Subscribes to a contract view method and returns a stream of state updates.
    ///
    /// The returned stream polls the contract every 200 ms.
    ///
    /// # Type Parameter
    ///
    /// `T` is the deserialized return type of the contract method.
    fn subscribe<T>(
        &self,
        contract: AccountId,
        view_method: &str,
    ) -> impl Future<Output = impl StreamContractState<T> + Send> + Send
    where
        T: DeserializeOwned + Send + Clone,
    {
        ContractMethodSubscription::new(self.clone(), contract, view_method, b"{}".to_vec())
    }
}

/// Blanket-implemented for all `T: HasViewContract`.
///
/// Performs a one-shot typed view call: serializes `args` as JSON, calls the
/// underlying [`ViewContract::view_raw`], and deserializes the response.
///
/// # Example
///
/// ```
/// use chain_gateway::mock::{MockChainState, Call};
/// use chain_gateway::state_viewer::ViewMethod;
/// use chain_gateway::types::{NoArgs, ObservedState};
///
/// #[tokio::main]
/// async fn main() {
///     let viewer = MockChainState::builder()
///         .with_syncing_status(Ok(false))
///         .with_view_function_query_response(Ok(ObservedState {
///             observed_at: 1.into(),
///             value: br#""hello""#.to_vec(),
///         }))
///         .build();
///
///     let result: ObservedState<String> = viewer
///         .view("contract.near".parse().unwrap(), "get_greeting", &NoArgs {})
///         .await
///         .unwrap();
///
///     assert_eq!(result.value, "hello");
///     assert_eq!(result.observed_at, 1.into());
/// }
/// ```
pub trait ViewMethod: ViewContract {
    fn view<Arg, Res>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> impl Future<Output = Result<ObservedState<Res>, ChainGatewayError>> + Send
    where
        Arg: Serialize + Sync,
        Res: DeserializeOwned + Send + Clone,
    {
        async move {
            let args: Vec<u8> =
                serde_json::to_vec(args).map_err(|err| ChainGatewayError::Serialization {
                    op: ChainGatewayOp::ViewCall {
                        account_id: contract_id.to_string(),
                        method_name: method_name.to_string(),
                    },
                    source: Arc::new(err),
                })?;
            let res = self.view_raw(&contract_id, method_name, &args).await?;
            let value = serde_json::from_slice::<Res>(&res.value).map_err(|err| {
                ChainGatewayError::Deserialization {
                    source: Arc::new(err),
                }
            })?;

            Ok(ObservedState {
                observed_at: res.observed_at,
                value,
            })
        }
    }
}

/// A watch-like stream of contract state changes.
///
/// Call [`latest()`](StreamContractState::latest) to get the most recent value,
/// and [`changed()`](StreamContractState::changed) to wait for the next update.
/// Only actual value changes (different bytes) trigger a notification (block
/// height increases alone do not).
pub trait StreamContractState<Res> {
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError>;
    /// Waits until the observed value changes.
    fn changed(&mut self) -> impl Future<Output = Result<(), ChainGatewayError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::ViewContract;
    use crate::errors::{ChainGatewayError, ChainGatewayOp};
    use crate::mock::{Call, MockChainState, MockError};
    use crate::state_viewer::{StreamContractState, SubscribeContractState, ViewMethod};
    use crate::types::{NoArgs, RawObservedState};
    use near_account_id::AccountId;
    use rand::distributions::{Alphanumeric, DistString};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// Produces a deterministic `(Call, RawObservedState)` pair from the given RNG
    /// so every test uses unique but reproducible data.
    fn random_view_params(rng: &mut StdRng) -> (Call, RawObservedState) {
        let contract_id: AccountId = format!(
            "{}.testnet",
            Alphanumeric.sample_string(rng, 8).to_lowercase()
        )
        .parse()
        .unwrap();
        let method_name = Alphanumeric.sample_string(rng, 10);
        let args: Vec<u8> = (0..rng.gen_range(1..16)).map(|_| rng.r#gen()).collect();
        let block_height: u64 = rng.gen_range(1..1_000_000);
        let payload: Vec<u8> = (0..rng.gen_range(1..32)).map(|_| rng.r#gen()).collect();
        (
            Call {
                contract_id,
                method_name,
                args,
            },
            RawObservedState {
                observed_at: block_height.into(),
                value: payload,
            },
        )
    }

    #[tokio::test]
    async fn test_view_raw_returns_ok_on_success() {
        let mut rng = StdRng::seed_from_u64(1);
        let (call, response) = random_view_params(&mut rng);
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(response.clone()))
            .build();

        let state = viewer
            .view_raw(&call.contract_id, &call.method_name, &call.args)
            .await
            .unwrap();

        assert_eq!(state.observed_at, response.observed_at);
        assert_eq!(state.value, response.value);
    }

    #[tokio::test]
    async fn test_view_raw_queries_correct_arguments() {
        let mut rng = StdRng::seed_from_u64(2);
        let (call, response) = random_view_params(&mut rng);
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(response))
            .build();

        viewer
            .view_raw(&call.contract_id, &call.method_name, &call.args)
            .await
            .unwrap();

        assert_eq!(viewer.view_calls().await, vec![call]);
    }

    #[tokio::test]
    async fn test_view_raw_wraps_error_in_view_client() {
        let mut rng = StdRng::seed_from_u64(3);
        let (call, _response) = random_view_params(&mut rng);
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Err(MockError::SyncError))
            .build();

        let err = viewer
            .view_raw(&call.contract_id, &call.method_name, b"{}")
            .await
            .unwrap_err();

        match err {
            ChainGatewayError::ViewClient { op, source } => {
                let ChainGatewayOp::ViewCall {
                    account_id,
                    method_name: mn,
                } = op;
                assert_eq!(account_id, call.contract_id.to_string());
                assert_eq!(mn, call.method_name);
                assert_eq!(
                    source.downcast_ref::<MockError>(),
                    Some(&MockError::SyncError)
                );
            }
            other => panic!("expected ViewClient, got: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_view_raw_blocks_until_synced() {
        let mut rng = StdRng::seed_from_u64(4);
        let (call, response) = random_view_params(&mut rng);
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(true))
            .with_view_function_query_response(Ok(response))
            .build();

        let v = viewer.clone();
        let cid = call.contract_id.clone();
        let mn = call.method_name.clone();
        let a = call.args.clone();
        let handle = tokio::spawn(async move { v.view_raw(&cid, &mn, &a).await });

        // wait_for_full_sync polls every 500ms; advance past one interval
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        assert!(!handle.is_finished(), "should block while syncing");

        viewer.set_sync_response(Ok(false));

        // wait_for_full_sync polls every 500ms; advance past one interval
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_view_deserializes_response() {
        let mut rng = StdRng::seed_from_u64(5);
        let block_height: u64 = rng.gen_range(1..1_000_000);
        let value = Alphanumeric.sample_string(&mut rng, 12);
        let json_bytes = serde_json::to_vec(&value).unwrap();

        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: block_height.into(),
                value: json_bytes,
            }))
            .build();

        let result = viewer
            .view::<NoArgs, String>("a.testnet".parse().unwrap(), "m", &NoArgs {})
            .await
            .unwrap();

        assert_eq!(result.value, value);
        assert_eq!(result.observed_at, block_height.into());
    }

    #[tokio::test]
    async fn test_view_propagates_view_error() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Err(MockError::RpcError))
            .build();

        let err = viewer
            .view::<NoArgs, String>("a.testnet".parse().unwrap(), "m", &NoArgs {})
            .await
            .unwrap_err();

        assert!(matches!(err, ChainGatewayError::ViewClient { .. }));
    }

    #[tokio::test]
    async fn test_view_returns_deserialization_error_on_bad_bytes() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 1.into(),
                value: b"not valid json".to_vec(),
            }))
            .build();

        let err = viewer
            .view::<NoArgs, String>("a.testnet".parse().unwrap(), "m", &NoArgs {})
            .await
            .unwrap_err();

        assert!(matches!(err, ChainGatewayError::Deserialization { .. }));
    }

    // --- subscribe (SubscribeContractState) tests ---

    #[tokio::test(start_paused = true)]
    async fn test_subscribe_latest_returns_initial_value() {
        let mut rng = StdRng::seed_from_u64(8);
        let block_height: u64 = rng.gen_range(1..1_000_000);
        let value = Alphanumeric.sample_string(&mut rng, 12);
        let json_bytes = serde_json::to_vec(&value).unwrap();

        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: block_height.into(),
                value: json_bytes,
            }))
            .build();

        let mut sub = viewer
            .subscribe::<String>("a.testnet".parse().unwrap(), "m")
            .await;

        let state = sub.latest().unwrap();
        assert_eq!(state.value, value);
        assert_eq!(state.observed_at, block_height.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscribe_latest_returns_deserialization_error() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 1.into(),
                value: b"not json".to_vec(),
            }))
            .build();

        let mut sub = viewer
            .subscribe::<String>("a.testnet".parse().unwrap(), "m")
            .await;

        assert!(matches!(
            sub.latest().unwrap_err(),
            ChainGatewayError::Deserialization { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscribe_changed_fires_on_value_change() {
        let mut rng = StdRng::seed_from_u64(10);
        let initial = Alphanumeric.sample_string(&mut rng, 10);
        let updated = Alphanumeric.sample_string(&mut rng, 10);

        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_function_query_response(Ok(RawObservedState {
                observed_at: 1.into(),
                value: serde_json::to_vec(&initial).unwrap(),
            }))
            .build();

        let mut sub = viewer
            .subscribe::<String>("a.testnet".parse().unwrap(), "m")
            .await;
        assert_eq!(sub.latest().unwrap().value, initial);

        viewer
            .set_view_response(Ok(RawObservedState {
                observed_at: 2.into(),
                value: serde_json::to_vec(&updated).unwrap(),
            }))
            .await;

        // Wait for change to be propagated
        tokio::time::timeout(std::time::Duration::from_secs(2), sub.changed())
            .await
            .expect("changed() should resolve")
            .unwrap();

        assert_eq!(sub.latest().unwrap().value, updated);
    }
}
