use assert_matches::assert_matches;
use chain_gateway::errors::ChainGatewayError;
use chain_gateway::state_viewer::WatchContractState;
use chain_gateway::state_viewer::{SubscribeToContractMethod, ViewMethod};
use chain_gateway::types::NoArgs;
use chain_gateway::types::ObservedState;
use common::{TEST_CONTRACT_ACCOUNT, TEST_METHOD, TEST_STRING, setup_chain_gateway};

mod common;

/// spawns a local neard node, inserts a test contract and checks if viewing a valid contract method succeeds
#[tokio::test]
async fn test_view_method_contract_state() {
    let (gw, _dir) = setup_chain_gateway().await;

    let value: ObservedState<String> = gw
        .view_method(
            TEST_CONTRACT_ACCOUNT.parse().unwrap(),
            TEST_METHOD,
            &NoArgs {},
        )
        .await
        .expect("view call should succeed");

    assert_eq!(value.value, TEST_STRING);
}

/// spawns a local neard node, inserts a test contract and checks if viewing an invalid contract method fails
#[tokio::test]
async fn test_view_method_nonexistent_method_returns_error() {
    let (gw, _dir) = setup_chain_gateway().await;
    let result = gw
        .view_method::<NoArgs, String>(
            TEST_CONTRACT_ACCOUNT.parse().unwrap(),
            "nonexistent",
            &NoArgs {},
        )
        .await;

    let err = result.expect_err("calling a nonexistent method should fail");
    assert_matches!(err, ChainGatewayError::ViewError { .. });
}

/// Spawns a local neard node, inserts a test contract and checks if subscribing to the state
/// succeeds
#[tokio::test]
async fn test_subscription_receives_initial_value() {
    let (gw, _dir) = setup_chain_gateway().await;

    let mut sub = gw
        .subscribe_to_contract_method::<String>(TEST_CONTRACT_ACCOUNT.parse().unwrap(), TEST_METHOD)
        .await;

    let res = sub.latest().expect("subscription latest should succeed");
    assert_eq!(res.value, TEST_STRING);
}
