use assert_matches::assert_matches;
use chain_gateway::errors::NearViewClientError;
use chain_gateway_test_contract::consts::{DEFAULT_VALUE, VIEW_VALUE};
use near_contract_transport::{
    Json, ObservedState, TransportError, ViewArgs, ViewContract, WatchContractState,
};

use crate::common::localnet::Localnet;

/// Checks if viewing a valid contract method succeeds
#[tokio::test]
async fn test_view_method_contract_state() {
    let localnet = Localnet::new().await;
    let contract_id = localnet.contract.account_id.clone();
    let observer_gw = &localnet.observer.chain_gateway;

    let value: ObservedState<String> = observer_gw
        .view::<_, Json>(contract_id, ViewArgs::no_args(VIEW_VALUE))
        .await
        .expect("view call should succeed");

    assert_eq!(value.value, DEFAULT_VALUE);
    localnet.shutdown().await;
}

/// Checks if viewing an invalid contract method fails
#[tokio::test]
async fn test_view_method_nonexistent_method_returns_error() {
    let localnet = Localnet::new().await;
    let contract_id = localnet.contract.account_id.clone();
    let observer_gw = &localnet.observer.chain_gateway;

    let result = observer_gw
        .view::<String, Json>(contract_id, ViewArgs::no_args("nonexistent"))
        .await;

    let err = result.expect_err("calling a nonexistent method should fail");
    assert_matches!(
        err,
        TransportError::View(NearViewClientError::ResponseError { .. })
    );
    localnet.shutdown().await;
}

/// Checks if subscribing to the state succeeds
#[tokio::test]
async fn test_subscription_receives_initial_value() {
    let localnet = Localnet::new().await;
    let contract_id = localnet.contract.account_id.clone();
    let observer_gw = &localnet.observer.chain_gateway;

    {
        let mut sub = observer_gw
            .view::<String, Json>(contract_id, ViewArgs::no_args(VIEW_VALUE))
            .subscribe()
            .await;

        let res = sub.latest().expect("subscription latest should succeed");
        assert_eq!(res.value, DEFAULT_VALUE);
    }
    localnet.shutdown().await;
}
