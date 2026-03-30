use std::time::{Duration, Instant};

use chain_gateway::Gas;
use chain_gateway::types::NoArgs;
use chain_gateway::{state_viewer::ViewMethod, transaction_sender::SubmitFunctionCall};
use chain_gateway_test_contract::args::{Call, make_set_value_args};
use chain_gateway_test_contract::consts::{DEFAULT_VALUE, VIEW};

use crate::common::localnet::LocalnetBuilder;

/// This integration test uses the `ChainGateway` struct to spin up two neard nodes
/// for a localnet. One of the nodes is an observer node (what the MPC node would be running),
/// the other is a validator node.
/// A smart contract is injected in the genesis file to simplify testing.
///
/// The test uses the chain gateway of the observer node to verify that view functions of
/// the smart contract yield expected results. It constructs a `TransactionSigner` from
/// the private key of the contract account and has the observer's chain gateway
/// sign and route the transaction.
#[tokio::test]
async fn test_submit_set_value_and_read_back() {
    let localnet = LocalnetBuilder::new();
    let (localnet, user) = localnet.with_test_account("dummy_user.near".parse().unwrap());
    let signer = user.signer;
    let localnet = localnet.build().await;
    let observer_gw = &localnet.observer.chain_gateway;
    let contract_id = &localnet.contract.account_id;

    // Verify initial state: get_value should return DEFAULT_VALUE
    let initial: chain_gateway::types::ObservedState<String> = observer_gw
        .view_method(&contract_id, VIEW, &NoArgs {})
        .await
        .expect("initial view call should succeed");

    assert_eq!(initial.value, DEFAULT_VALUE);

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
            contract_id.clone(),
            method,
            args,
            Gas::from_teragas(tera_gas),
        )
        .await
        .unwrap();

    // Poll get_value until state reflects the new value.
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        localnet.assert_nodes_alive();

        let result: chain_gateway::types::ObservedState<String> = observer_gw
            .view_method(&contract_id, VIEW, &NoArgs {})
            .await
            .expect("view call should succeed");

        if result.value == new_value {
            break;
        }

        assert!(
            Instant::now() < deadline,
            "Timed out waiting for state change. Last value: {:?}",
            result.value,
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    localnet.shutdown().await;
}
