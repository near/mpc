use assert_matches::assert_matches;
use chain_gateway::errors::ChainGatewayError;
use chain_gateway::state_viewer::WatchContractState;
use chain_gateway::state_viewer::{SubscribeToContractMethod, ViewMethod};
use chain_gateway::types::NoArgs;
use chain_gateway::types::ObservedState;
use chain_gateway_test_contract::{DEFAULT_VALUE, VIEW_METHOD};

use crate::common::localnet::Localnet;

/// Checks if viewing a valid contract method succeeds
#[tokio::test]
async fn test_view_method_contract_state() {
    let localnet = Localnet::new().await;
    let contract_account_id = localnet.contract.account_id.clone();

    let value: ObservedState<String> = localnet
        .observer
        .chain_gateway
        .view_method(contract_account_id, VIEW_METHOD, &NoArgs {})
        .await
        .expect("view call should succeed");

    assert_eq!(value.value, DEFAULT_VALUE);
}

/// Checks if viewing an invalid contract method fails
#[tokio::test]
async fn test_view_method_nonexistent_method_returns_error() {
    let localnet = Localnet::new().await;
    let contract_account_id = localnet.contract.account_id.clone();

    let result = localnet
        .observer
        .chain_gateway
        .view_method::<NoArgs, String>(contract_account_id, "nonexistent", &NoArgs {})
        .await;

    let err = result.expect_err("calling a nonexistent method should fail");
    assert_matches!(err, ChainGatewayError::ViewError { .. });
}

/// Checks if subscribing to the state succeeds
#[tokio::test]
async fn test_subscription_receives_initial_value() {
    let localnet = Localnet::new().await;
    let contract_account_id = localnet.contract.account_id.clone();

    let mut sub = localnet
        .observer
        .chain_gateway
        .subscribe_to_contract_method::<String>(contract_account_id, VIEW_METHOD)
        .await;

    let res = sub.latest().expect("subscription latest should succeed");
    assert_eq!(res.value, DEFAULT_VALUE);
}
