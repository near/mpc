use std::time::Duration;

use chain_gateway_test_contract::{
    args::{TestContract, make_set_value_args},
    consts::DEFAULT_VALUE,
};
use near_contract_transport::watch::Subscribe;
use near_kit_primitives::Contract as _;

use crate::common::localnet::LocalnetBuilder;
use crate::common::send;

/// Checks if subscribing to the state succeeds
#[tokio::test]
async fn test_subscription() {
    let mut localnet = LocalnetBuilder::new()
        .with_test_account("dummy_user.near".parse().unwrap())
        .build()
        .await;
    let signer = localnet.take_test_account().signer;
    let observer_gw = &localnet.observer.chain_gateway;
    let contract_id = localnet.contract.account_id.clone();

    let contract = TestContract::client(observer_gw.clone(), contract_id.clone());
    let mut sub = contract
        .view_value()
        .subscribe(observer_gw.poll_interval())
        .await;

    let res = sub
        .borrow_and_update()
        .clone()
        .expect("subscription latest should succeed");
    assert_eq!(res.result, DEFAULT_VALUE);

    // Submit set_value transaction via the observer, using a separate user account
    let new_value = "updated by sender test";

    let call = make_set_value_args(new_value);

    send(observer_gw, &signer, contract_id, call).await;

    tokio::time::timeout(Duration::from_secs(30), sub.changed())
        .await
        .expect("subscription should fire on change")
        .expect("changed should ");
    let result = sub.borrow().clone().unwrap();
    assert_eq!(result.result, new_value);

    drop(sub);
    localnet.shutdown().await;
}
