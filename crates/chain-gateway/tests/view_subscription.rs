use std::time::Duration;

use chain_gateway::{
    Gas,
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::SubmitFunctionCall,
};
use chain_gateway_test_contract::{DEFAULT_VALUE, SET_VALUE, VIEW_METHOD};

use crate::common::localnet::LocalnetBuilder;

/// Checks if subscribing to the state succeeds
#[tokio::test]
async fn test_subscription() {
    let contract_id: near_account_id::AccountId =
        "test-contract-subscription.near".parse().unwrap();
    let localnet = LocalnetBuilder::new(contract_id.clone());
    let (localnet, user) = localnet.with_test_account("dummy_user.near".parse().unwrap());
    let signer = user.signer;
    let localnet = localnet.build().await;
    let observer_gw = &localnet.observer.chain_gateway;

    let mut sub = observer_gw
        .subscribe_to_contract_method::<String>(contract_id.clone(), VIEW_METHOD)
        .await;

    let res = sub.latest().expect("subscription latest should succeed");
    assert_eq!(res.value, DEFAULT_VALUE);

    // Submit set_value transaction via the observer, using a separate user account
    let new_value = "updated by sender test";

    observer_gw
        .submit_function_call_tx(
            &signer,
            contract_id.clone(),
            SET_VALUE.to_string(),
            serde_json::to_vec(&serde_json::json!({ "value": new_value })).unwrap(),
            Gas::from_teragas(30),
        )
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(30), sub.changed())
        .await
        .expect("expect subscription to fire on change")
        .expect("expect changed to succeed");
    let result = sub.latest().unwrap();
    assert_eq!(result.value, new_value);

    drop(sub);
    localnet.shutdown().await;
}
