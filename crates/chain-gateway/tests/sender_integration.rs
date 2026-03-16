use std::sync::Arc;
use std::time::{Duration, Instant};

use chain_gateway::state_viewer::ViewMethod;
use chain_gateway::transaction_sender::{SubmitFunctionCall, TransactionSigner};
use chain_gateway::types::NoArgs;
use chain_gateway_test_contract::{DEFAULT_VALUE, VIEW_METHOD};
use common::localnet::Localnet;

use super::common;

/// Sends a `set_value` transaction via the observer node, and verifies the state change via `get_value`.
#[test]
fn test_submit_set_value_and_read_back() {
    common::run_localnet_test(|localnet| async move {
        let Localnet {
            observer, contract, ..
        } = localnet;
        let contract_id = contract.account_id;

        // Verify initial state: get_value should return DEFAULT_VALUE
        let initial: chain_gateway::types::ObservedState<String> = observer
            .chain_gateway
            .view_method(contract_id.clone(), VIEW_METHOD, &NoArgs {})
            .await
            .expect("initial view call should succeed");

        assert_eq!(initial.value, DEFAULT_VALUE);

        // Submit set_value transaction via the validator for reliable mempool insertion.
        let new_value = "updated by sender test";
        let args = serde_json::json!({ "value": new_value });
        let signer = Arc::new(TransactionSigner::from_key(
            contract_id.clone(),
            contract.signing_key,
        ));

        observer
            .chain_gateway
            .submit_function_call_tx(
                &signer,
                contract_id.clone(),
                "set_value".to_string(),
                serde_json::to_vec(&args).unwrap(),
                near_indexer_primitives::types::Gas::from_teragas(30),
            )
            .await
            .expect("submit_function_call_tx should succeed");

        // Poll get_value until state reflects the new value.
        let deadline = Instant::now() + Duration::from_secs(60);

        loop {
            let result: chain_gateway::types::ObservedState<String> = observer
                .chain_gateway
                .view_method(contract_id.clone(), VIEW_METHOD, &NoArgs {})
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
        Ok(())
    });
}
