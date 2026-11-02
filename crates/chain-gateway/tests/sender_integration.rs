use std::time::{Duration, Instant};

use chain_gateway_test_contract::args::{TestContract, make_set_value_args};
use chain_gateway_test_contract::consts::DEFAULT_VALUE;
use near_kit_primitives::Contract as _;

use crate::common::localnet::LocalnetBuilder;
use crate::common::send;

/// This integration test uses the [`ChainGateway`] struct to spin up two neard nodes
/// for a localnet. One of the nodes is an observer node (what the MPC node would be running),
/// the other is a validator node.
/// A smart contract is injected in the genesis file to simplify testing.
///
/// The test uses the chain gateway of the observer node to verify that view functions of
/// the smart contract yield expected results. It signs with an
/// `InMemorySigner` holding the contract account's private key and has the observer's
/// chain gateway route the transaction through a `GatewaySender`.
#[tokio::test]
async fn test_submit_set_value_and_read_back() {
    let mut localnet = LocalnetBuilder::new()
        .with_test_account("dummy_user.near".parse().unwrap())
        .build()
        .await;
    let signer = localnet.take_test_account().signer;
    let observer_gw = &localnet.observer.chain_gateway;
    let contract_id = &localnet.contract.account_id;

    // Verify initial state: get_value should return DEFAULT_VALUE
    let contract = TestContract::client(observer_gw.clone(), contract_id.clone());
    let initial = contract
        .view_value()
        .await
        .expect("initial view call should succeed");

    assert_eq!(initial, DEFAULT_VALUE);

    // Submit set_value transaction via the observer, using a separate user account
    let new_value = "updated by sender test";
    let call = make_set_value_args(new_value);

    send(observer_gw, &signer, contract_id.clone(), call).await;

    // Poll get_value until state reflects the new value.
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        localnet.assert_nodes_alive();

        let result = contract
            .view_value()
            .await
            .expect("view call should succeed");

        if result == new_value {
            break;
        }

        assert!(
            Instant::now() < deadline,
            "Timed out waiting for state change. Last value: {:?}",
            result,
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    localnet.shutdown().await;
}
