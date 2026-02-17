use crate::sandbox::common::{init_env, SandboxTestSetup};
use crate::sandbox::utils::consts::{ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN};
use assert_matches::assert_matches;
use serde_json::json;

#[tokio::test]
async fn vote_foreign_chain_policy_rejects_empty_rpc_providers() {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    // When: a participant votes with a policy containing an empty RPC providers set
    let transaction_result = mpc_signer_accounts[0]
        .call(contract.id(), "vote_foreign_chain_policy")
        .args_json(json!({
            "policy": {
                "chains": {
                    "Ethereum": []
                }
            }
        }))
        .transact()
        .await
        .unwrap()
        .into_result();

    // Then: the transaction fails because NonEmptyBTreeSet rejects empty arrays
    assert_matches!(
        transaction_result,
        Err(_),
        "transaction should fail when RPC providers set is empty"
    );
}

#[tokio::test]
async fn vote_foreign_chain_policy_accepts_valid_policy() {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    // When: a participant votes with a valid policy containing non-empty RPC providers
    let transaction_result = mpc_signer_accounts[0]
        .call(contract.id(), "vote_foreign_chain_policy")
        .args_json(json!({
            "policy": {
                "chains": {
                    "Ethereum": [{"rpc_url": "https://rpc.example.com"}]
                }
            }
        }))
        .transact()
        .await
        .unwrap()
        .into_result();

    // Then: the transaction succeeds
    assert_matches!(
        transaction_result,
        Ok(_),
        "transaction should succeed with a valid non-empty RPC providers set"
    );
}
