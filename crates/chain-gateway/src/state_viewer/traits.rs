use std::future::Future;

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::primitives::IsSyncing;
use near_account_id::AccountId;
use near_contract_transport::{BlockHeight, ObservedState};
use near_contract_transport::{ViewArgs, ViewContract};
use serde::de::DeserializeOwned;

use super::subscription::ContractMethodSubscription;

/// Provides a subscribe-and-poll interface for observing contract state changes.
/// Polls the view method every 200 ms and emits change notifications only when
/// the returned bytes differ.
///
/// # Example
///
/// ```
/// use near_contract_transport::ViewArgs;
/// use chain_gateway::mock::{MockChainState, Call};
/// use chain_gateway::state_viewer::{WatchContractState, SubscribeToContractMethod};
/// use near_contract_transport::ObservedState;
///
/// #[tokio::main]
/// async fn main() {
///     let viewer = MockChainState::builder()
///         .with_syncing_status(Ok(false))
///         .with_view_response(Ok(ObservedState {
///             observed_at: 1.into(),
///             value: br#""hello""#.to_vec(),
///         }))
///         .build();
///
///     let mut stream = viewer
///         .subscribe_to_contract_method::<String>(
///             "contract.near".parse().unwrap(),
///             ViewArgs::no_args("get_greeting"),
///         )
///         .await;
///
///     let state = stream.latest().unwrap();
///     assert_eq!(state.value, "hello");
/// }
/// ```
pub trait SubscribeToContractMethod {
    /// Subscribes to a contract view method and returns a stream of state updates.
    ///
    /// The returned stream polls the contract every 200 ms.
    ///
    /// # Type Parameter
    ///
    /// `T` is the deserialized return type of the contract method.
    fn subscribe_to_contract_method<T>(
        &self,
        contract: AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = impl WatchContractState<T> + Send> + Send
    where
        T: DeserializeOwned + Send + Clone;
}

/// Performs a typed view call: calls the contract and deserializes the
/// JSON response.
///
/// # Example
///
/// ```
/// use near_contract_transport::ViewArgs;
/// use chain_gateway::mock::{MockChainState, Call};
/// use chain_gateway::state_viewer::ViewMethod;
/// use near_contract_transport::ObservedState;
///
/// #[tokio::main]
/// async fn main() {
///     let viewer = MockChainState::builder()
///         .with_syncing_status(Ok(false))
///         .with_view_response(Ok(ObservedState {
///             observed_at: 1.into(),
///             value: br#""hello""#.to_vec(),
///         }))
///         .build();
///
///     let result: ObservedState<String> = viewer
///         .view_method(
///             "contract.near".parse().unwrap(),
///             ViewArgs::no_args("get_greeting"),
///         )
///         .await
///         .unwrap();
///
///     assert_eq!(result.value, "hello");
///     assert_eq!(result.observed_at, 1.into());
/// }
/// ```
pub trait ViewMethod {
    fn view_method<Res>(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState<Res>, ChainGatewayError>> + Send
    where
        Res: DeserializeOwned + Send;
}

/// All other viewer traits are derived from this one. Subscriptions track the
/// height a value was observed at, so the backend must report one.
pub(crate) trait ViewRaw: IsSyncing + ViewContract<ObservedAt = BlockHeight> {
    // waits until self is synced and then queries the view function
    fn view_raw(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState, ChainGatewayError>> + Send;
}

/// A watch-like stream of contract state changes.
///
/// Call [`latest()`](WatchContractState::latest) to get the most recent value,
/// and [`changed()`](WatchContractState::changed) to wait for the next update.
/// Only actual value changes (different bytes) trigger a notification (block
/// height increases alone do not).
pub trait WatchContractState<Res> {
    /// Returns the last value observed on chain and the block height at which it was first
    /// observed.
    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError>;
    /// Waits until the observed value changes.
    fn changed(&mut self) -> impl Future<Output = Result<(), ChainGatewayError>> + Send;
}

impl<T> ViewRaw for T
where
    T: IsSyncing + ViewContract<ObservedAt = BlockHeight>,
    <T as ViewContract>::Error: std::fmt::Display,
{
    async fn view_raw(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, ChainGatewayError> {
        self.wait_for_full_sync().await;
        let method_name = view_args.method_name.clone();
        self.view_contract(contract_id, view_args)
            .await
            .map_err(|err| ChainGatewayError::ViewError {
                op: ChainGatewayOp::ViewQuery {
                    account_id: contract_id.to_string(),
                    method_name,
                },
                message: err.to_string(),
            })
    }
}

impl<V: ViewRaw + Clone> SubscribeToContractMethod for V {
    fn subscribe_to_contract_method<T>(
        &self,
        contract: AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = impl WatchContractState<T> + Send> + Send
    where
        T: DeserializeOwned + Send + Clone,
    {
        ContractMethodSubscription::new(self.clone(), contract, view_args)
    }
}

impl<T: ViewRaw> ViewMethod for T {
    async fn view_method<Res>(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState<Res>, ChainGatewayError>
    where
        Res: DeserializeOwned + Send,
    {
        deserialize_observed(self.view_raw(&contract_id, view_args).await?)
    }
}

pub(crate) fn deserialize_observed<Res: DeserializeOwned>(
    observed: ObservedState,
) -> Result<ObservedState<Res>, ChainGatewayError> {
    observed
        .deserialize()
        .map_err(|err| ChainGatewayError::Deserialization {
            message: err.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::ViewRaw;
    use crate::errors::{ChainGatewayError, ChainGatewayOp};
    use crate::mock::{Call, MockChainState, MockError};
    use crate::state_viewer::{SubscribeToContractMethod, ViewMethod, WatchContractState};
    use assert_matches::assert_matches;
    use near_account_id::AccountId;
    use near_contract_transport::ObservedState;
    use near_contract_transport::ViewArgs;
    use rand::distributions::{Alphanumeric, DistString};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// Produces a deterministic `(Call, ObservedState)` pair from the given RNG
    /// so every test uses unique but reproducible data.
    fn random_view_params(rng: &mut StdRng) -> (Call, ObservedState) {
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
            ObservedState {
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
            .with_view_response(Ok(response.clone()))
            .build();

        let state = viewer
            .view_raw(
                &call.contract_id,
                ViewArgs::new(call.method_name.clone(), call.args.clone()),
            )
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
            .with_view_response(Ok(response))
            .build();

        viewer
            .view_raw(
                &call.contract_id,
                ViewArgs::new(call.method_name.clone(), call.args.clone()),
            )
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
            .with_view_response(Err(MockError::SyncError))
            .build();

        let err = viewer
            .view_raw(&call.contract_id, ViewArgs::no_args(&call.method_name))
            .await
            .unwrap_err();

        assert_eq!(
            err,
            ChainGatewayError::ViewError {
                op: ChainGatewayOp::ViewQuery {
                    account_id: call.contract_id.to_string(),
                    method_name: call.method_name,
                },
                message: MockError::SyncError.to_string(),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_view_raw_blocks_until_synced() {
        let mut rng = StdRng::seed_from_u64(4);
        let (call, response) = random_view_params(&mut rng);
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(true))
            .with_view_response(Ok(response))
            .build();

        let v = viewer.clone();
        let cid = call.contract_id.clone();
        let mn = call.method_name.clone();
        let a = call.args.clone();
        let handle = tokio::spawn(async move { v.view_raw(&cid, ViewArgs::new(mn, a)).await });

        // wait_for_full_sync polls every 500ms; advance past one interval
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        assert!(!handle.is_finished(), "should block while syncing");

        viewer.set_sync_response(Ok(false));

        // wait_for_full_sync polls every 500ms; advance past one interval
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_view_method_deserializes_response() {
        let mut rng = StdRng::seed_from_u64(5);
        let block_height: u64 = rng.gen_range(1..1_000_000);
        let value = Alphanumeric.sample_string(&mut rng, 12);
        let json_bytes = serde_json::to_vec(&value).unwrap();

        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_response(Ok(ObservedState {
                observed_at: block_height.into(),
                value: json_bytes,
            }))
            .build();

        let result = viewer
            .view_method::<String>("a.testnet".parse().unwrap(), ViewArgs::no_args("m"))
            .await
            .unwrap();

        assert_eq!(result.value, value);
        assert_eq!(result.observed_at, block_height.into());
    }

    #[tokio::test]
    async fn test_view_method_propagates_view_error() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_response(Err(MockError::ViewClientError))
            .build();

        let account_id: AccountId = "a.testnet".parse().unwrap();
        let method_name = "m".to_string();
        let err = viewer
            .view_method::<String>(account_id.clone(), ViewArgs::no_args(&method_name))
            .await
            .unwrap_err();

        assert_eq!(
            err,
            ChainGatewayError::ViewError {
                op: ChainGatewayOp::ViewQuery {
                    account_id: account_id.to_string(),
                    method_name
                },
                message: MockError::ViewClientError.to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_view_returns_deserialization_error_on_bad_bytes() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_response(Ok(ObservedState {
                observed_at: 1.into(),
                value: b"not valid json".to_vec(),
            }))
            .build();

        let contract_id: AccountId = "a.testnet".parse().unwrap();
        let method_name: String = "m".into();
        let err = viewer
            .view_method::<String>(contract_id, ViewArgs::no_args(&method_name))
            .await
            .unwrap_err();

        assert_matches!(err, ChainGatewayError::Deserialization { .. });
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscribe_latest_returns_initial_value() {
        let mut rng = StdRng::seed_from_u64(8);
        let block_height: u64 = rng.gen_range(1..1_000_000);
        let value = Alphanumeric.sample_string(&mut rng, 12);
        let json_bytes = serde_json::to_vec(&value).unwrap();

        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_response(Ok(ObservedState {
                observed_at: block_height.into(),
                value: json_bytes,
            }))
            .build();

        let mut sub = viewer
            .subscribe_to_contract_method::<String>(
                "a.testnet".parse().unwrap(),
                ViewArgs::no_args("m"),
            )
            .await;

        let state = sub.latest().unwrap();
        assert_eq!(state.value, value);
        assert_eq!(state.observed_at, block_height.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscribe_latest_returns_deserialization_error() {
        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_response(Ok(ObservedState {
                observed_at: 1.into(),
                value: b"not json".to_vec(),
            }))
            .build();

        let contract_id: AccountId = "a.testnet".parse().unwrap();
        let method_name: String = "m".into();
        let err = {
            let mut sub = viewer
                .subscribe_to_contract_method::<String>(
                    contract_id.clone(),
                    ViewArgs::no_args(&method_name),
                )
                .await;

            sub.latest().unwrap_err()
        };
        assert_matches!(err, ChainGatewayError::Deserialization { .. });
    }

    #[tokio::test(start_paused = true)]
    async fn test_subscribe_changed_fires_on_value_change() {
        let mut rng = StdRng::seed_from_u64(10);
        let initial = Alphanumeric.sample_string(&mut rng, 10);
        let updated = Alphanumeric.sample_string(&mut rng, 10);

        let viewer = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_view_response(Ok(ObservedState {
                observed_at: 1.into(),
                value: serde_json::to_vec(&initial).unwrap(),
            }))
            .build();

        let mut sub = viewer
            .subscribe_to_contract_method::<String>(
                "a.testnet".parse().unwrap(),
                ViewArgs::no_args("m"),
            )
            .await;
        assert_eq!(sub.latest().unwrap().value, initial);

        viewer
            .set_view_response(Ok(ObservedState {
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
