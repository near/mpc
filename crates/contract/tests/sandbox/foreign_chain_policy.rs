#![allow(non_snake_case)]

use crate::sandbox::common::{init_env, SandboxTestSetup};
use crate::sandbox::utils::consts::{ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN};
use assert_matches::assert_matches;
use contract_interface::method_names::{
    GET_FOREIGN_CHAIN_POLICY_PROPOSALS, VOTE_FOREIGN_CHAIN_POLICY,
};
use serde_json::json;

#[tokio::test]
async fn vote_foreign_chain_policy__should_reject_empty_rpc_providers() {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    // When: a participant votes with a policy containing an empty RPC providers set
    let transaction_result = mpc_signer_accounts[0]
        .call(contract.id(), VOTE_FOREIGN_CHAIN_POLICY)
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
        .call(contract.id(), VOTE_FOREIGN_CHAIN_POLICY)
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

#[tokio::test]
async fn vote_foreign_chain_policy_deduplicates_duplicate_rpc_providers() {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    // When: a participant votes with a policy containing duplicate RPC providers
    let transaction_result = mpc_signer_accounts[0]
        .call(contract.id(), VOTE_FOREIGN_CHAIN_POLICY)
        .args_json(json!({
            "policy": {
                "chains": {
                    "Ethereum": [
                        {"rpc_url": "https://rpc.example.com"},
                        {"rpc_url": "https://rpc.example.com"},
                        {"rpc_url": "https://rpc2.example.com"}
                    ]
                }
            }
        }))
        .transact()
        .await
        .unwrap()
        .into_result();

    // Then: the transaction succeeds (duplicates are silently ignored by BTreeSet)
    assert_matches!(
        transaction_result,
        Ok(_),
        "transaction should succeed even with duplicate RPC providers"
    );

    // And: the stored vote contains only unique entries.
    // Deserialize as raw JSON to avoid client-side BTreeSet deduplication hiding the result.
    let votes: serde_json::Value = contract
        .view("get_foreign_chain_policy_proposals")
        .await
        .unwrap()
        .json()
        .unwrap();
    let voter_id = mpc_signer_accounts[0].id().to_string();
    let ethereum_providers = &votes["proposal_by_account"][&voter_id]["chains"]["Ethereum"];
    let providers = ethereum_providers.as_array().unwrap();
    assert_eq!(
        providers.len(),
        2,
        "duplicate RPC providers should be deduplicated"
    );
}

#[tokio::test]
async fn vote_foreign_chain_policy_deduplicates_duplicate_chain_keys() {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    // When: a participant votes with a policy containing duplicate chain keys.
    // The json! macro cannot represent duplicate object keys, so we use raw JSON bytes.
    // serde deserializes duplicate keys into a BTreeMap by keeping the last value.
    let raw_json = br#"{
        "policy": {
            "chains": {
                "Ethereum": [{"rpc_url": "https://first.example.com"}],
                "Ethereum": [{"rpc_url": "https://second.example.com"}]
            }
        }
    }"#;
    let transaction_result = mpc_signer_accounts[0]
        .call(contract.id(), VOTE_FOREIGN_CHAIN_POLICY)
        .args(raw_json.to_vec())
        .transact()
        .await
        .unwrap()
        .into_result();

    // Then: the transaction succeeds (duplicate chain key is silently ignored by BTreeMap)
    assert_matches!(
        transaction_result,
        Ok(_),
        "transaction should succeed even with duplicate chain keys"
    );

    // And: only one Ethereum entry is stored (the last value wins).
    // Deserialize as raw JSON to avoid client-side BTreeMap deduplication hiding the result.
    let votes: serde_json::Value = contract
        .view(GET_FOREIGN_CHAIN_POLICY_PROPOSALS)
        .await
        .unwrap()
        .json()
        .unwrap();
    let voter_id = mpc_signer_accounts[0].id().to_string();
    let chains = &votes["proposal_by_account"][&voter_id]["chains"];
    let chains_obj = chains.as_object().unwrap();
    assert_eq!(
        chains_obj.len(),
        1,
        "duplicate chain keys should result in a single entry"
    );
    let ethereum_providers = chains_obj.get("Ethereum").unwrap().as_array().unwrap();
    assert_eq!(ethereum_providers.len(), 1);
    assert_eq!(
        ethereum_providers[0]["rpc_url"].as_str().unwrap(),
        "https://second.example.com",
        "the last duplicate chain entry should win"
    );
}
