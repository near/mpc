use assert_matches::assert_matches;
use chain_gateway::errors::ChainGatewayError;
use chain_gateway::state_viewer::WatchContractState;
use chain_gateway::state_viewer::{SubscribeToContractMethod, ViewMethod};
use chain_gateway::types::NoArgs;
use chain_gateway::types::ObservedState;
use chain_gateway_test_contract::consts::{DEFAULT_VALUE, VIEW};

use crate::common::localnet::Localnet;

/// Checks if viewing a valid contract method succeeds
#[tokio::test]
async fn test_view_method_contract_state() {
    let contract_id: near_account_id::AccountId = "test-contract-view.near".parse().unwrap();
    let localnet = Localnet::new(contract_id.clone()).await;
    let observer_gw = &localnet.observer.chain_gateway;

    let value: ObservedState<String> = observer_gw
        .view_method(contract_id, VIEW, &NoArgs {})
        .await
        .expect("view call should succeed");

    assert_eq!(value.value, DEFAULT_VALUE);
    localnet.shutdown().await;
}

/// Checks if viewing an invalid contract method fails
#[tokio::test]
async fn test_view_method_nonexistent_method_returns_error() {
    let contract_id: near_account_id::AccountId = "test-contract-view-error.near".parse().unwrap();
    let localnet = Localnet::new(contract_id.clone()).await;
    let observer_gw = &localnet.observer.chain_gateway;

    let result = observer_gw
        .view_method::<NoArgs, String>(contract_id, "nonexistent", &NoArgs {})
        .await;

    let err = result.expect_err("calling a nonexistent method should fail");
    assert_matches!(err, ChainGatewayError::ViewError { .. });
    localnet.shutdown().await;
}

/// Checks if subscribing to the state succeeds
#[tokio::test]
async fn test_subscription_receives_initial_value() {
    let contract_id: near_account_id::AccountId = "test-contract-subscribe.near".parse().unwrap();
    let localnet = Localnet::new(contract_id.clone()).await;
    let observer_gw = &localnet.observer.chain_gateway;

    {
        let mut sub = observer_gw
            .subscribe_to_contract_method::<String>(contract_id, VIEW)
            .await;

        let res = sub.latest().expect("subscription latest should succeed");
        assert_eq!(res.value, DEFAULT_VALUE);
    }
    localnet.shutdown().await;
}
