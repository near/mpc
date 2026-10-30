use chain_gateway::errors::NearViewClientError;
use chain_gateway_test_contract::args::TestContract;
use chain_gateway_test_contract::consts::DEFAULT_VALUE;
use near_contract_transport::watch::Subscribe;
use near_kit_primitives::{Contract as _, ContractError, View};
use std::assert_matches;

use crate::common::localnet::Localnet;

/// Checks if viewing a valid contract method succeeds
#[tokio::test]
async fn test_view_method_contract_state() {
    let localnet = Localnet::new().await;
    let contract_id = localnet.contract.account_id.clone();
    let observer_gw = &localnet.observer.chain_gateway;

    let value = TestContract::client(observer_gw.clone(), contract_id)
        .view_value()
        .await
        .expect("view call should succeed");

    assert_eq!(value, DEFAULT_VALUE);
    localnet.shutdown().await;
}

/// Checks if viewing an invalid contract method fails
#[tokio::test]
async fn test_view_method_nonexistent_method_returns_error() {
    let localnet = Localnet::new().await;
    let contract_id = localnet.contract.account_id.clone();
    let observer_gw = &localnet.observer.chain_gateway;

    let result = View::<_, String>::json(observer_gw.clone(), contract_id, "nonexistent").await;

    let err = result.expect_err("calling a nonexistent method should fail");
    assert_matches!(
        err,
        ContractError::Backend(NearViewClientError::ResponseError { .. })
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
        let contract = TestContract::client(observer_gw.clone(), contract_id);
        let sub = contract
            .view_value()
            .subscribe(observer_gw.poll_interval())
            .await;

        let res = sub
            .borrow()
            .clone()
            .expect("subscription latest should succeed");
        assert_eq!(res.result, DEFAULT_VALUE);
    }
    localnet.shutdown().await;
}
