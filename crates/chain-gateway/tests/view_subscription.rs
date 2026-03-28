use std::time::Duration;

use chain_gateway::{
    Gas,
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::SubmitFunctionCall,
};
use chain_gateway_test_contract::{
    args::{Call, make_set_value_args},
    consts::{DEFAULT_VALUE, VIEW},
};

use crate::common::localnet::LocalnetBuilder;

/// Checks if subscribing to the state succeeds
#[tokio::test]
async fn test_subscription() {
    let (localnet, user) =
        LocalnetBuilder::new().with_test_account("dummy_user.near".parse().unwrap());
    let signer = user.signer;
    let localnet = localnet.build().await;
    let observer_gw = &localnet.observer.chain_gateway;
    let contract_id = localnet.contract.account_id.clone();

    let mut sub = observer_gw
        .subscribe_to_contract_method::<String>(contract_id.clone(), VIEW)
        .await;

    let res = sub.latest().expect("subscription latest should succeed");
    assert_eq!(res.value, DEFAULT_VALUE);

    // Submit set_value transaction via the observer, using a separate user account
    let new_value = "updated by sender test";

    let Call {
        method,
        args,
        tera_gas,
        ..
    } = make_set_value_args(new_value);

    observer_gw
        .submit_function_call_tx(
            &signer,
            contract_id,
            method,
            args,
            Gas::from_teragas(tera_gas),
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
