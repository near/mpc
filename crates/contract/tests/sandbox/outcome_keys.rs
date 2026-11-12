use crate::sandbox::common::SandboxTestSetup;
use crate::sandbox::utils::transactions::CallMpcContract;
use near_mpc_contract_interface::types::{Ed25519PublicKey, OutcomeKeys};
use std::collections::BTreeMap;

#[tokio::test]
#[expect(non_snake_case)]
async fn register_outcome_key__should_make_the_key_readable_in_the_release_build() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder().build().await;
    let node = &mpc_signer_accounts[0];
    let outcome_key = Ed25519PublicKey::from([7u8; 32]);

    // When
    let result = node
        .call_mpc(contract.id())
        .register_outcome_key(outcome_key.clone())
        .await
        .unwrap();

    // Then
    assert!(result.is_success(), "{result:#?}");
    let outcome_keys = contract.outcome_keys().await.unwrap().value;
    assert_eq!(
        outcome_keys,
        OutcomeKeys::from(BTreeMap::from([(node.id().clone(), outcome_key)]))
    );
}
