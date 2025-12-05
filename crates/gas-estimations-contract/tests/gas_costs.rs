#![allow(clippy::disallowed_types)]
use near_sdk::{AccountId, Gas};
use near_workspaces::Account;
use serde_json::json;

async fn execute_transaction(
    user_account: &Account,
    contract_id: &AccountId,
    function: &str,
    args: serde_json::Value,
) -> Gas {
    let outcome = user_account
        .call(contract_id, function)
        .args_json(args)
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    println!("function: {function} gas: {}", outcome.total_gas_burnt);
    outcome.total_gas_burnt
}

#[tokio::test]
async fn test_cost_of_empty_call_not_loading_self() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await?;

    // The cost of this is around 1.7 Tgas as of 2025-12-08
    let cost = execute_transaction(&user_account, contract.id(), "noop", json!({})).await;

    let expected_upper_bound = Gas::from_tgas(2);
    assert!(
        cost < expected_upper_bound,
        "{cost} exceeded the expected value {expected_upper_bound}"
    );

    // The cost of this is around 6.5 Tgas as of 2025-12-08
    execute_transaction(
        &user_account,
        contract.id(),
        "increase_self_loading_cost",
        json!({"n": 100000}),
    )
    .await;

    let cost = execute_transaction(&user_account, contract.id(), "noop", json!({})).await;

    let expected_upper_bound = Gas::from_tgas(2);
    assert!(
        cost < expected_upper_bound,
        "{cost} exceeded the expected value {expected_upper_bound}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cost_of_empty_call_loading_self() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await.unwrap();

    let sandbox = near_workspaces::sandbox().await.unwrap();
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await.unwrap();

    // The cost of this is around 1.7 Tgas as of 2025-12-08
    let cost = execute_transaction(&user_account, contract.id(), "noop_with_self", json!({})).await;

    let expected_upper_bound = Gas::from_tgas(2);
    assert!(
        cost < expected_upper_bound,
        "{cost} exceeded the expected value {expected_upper_bound}"
    );

    // The cost of this is around 6.5 Tgas as of 2025-12-08
    execute_transaction(
        &user_account,
        contract.id(),
        "increase_self_loading_cost",
        json!({"n": 100000}),
    )
    .await;

    // The cost of this is around 3.6 Tgas as of 2025-12-08
    let cost = execute_transaction(&user_account, contract.id(), "noop_with_self", json!({})).await;

    let expected_lower_bound = Gas::from_tgas(3);
    assert!(
        cost > expected_lower_bound,
        "{cost} did not exceed the expected value {expected_lower_bound}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cost_of_many_insertions_in_map_std_vs_near() -> Result<(), Box<dyn std::error::Error>>
{
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await?;

    let elements = (0..1000u32).map(|i| (i, 2 * i)).collect::<Vec<_>>();

    // The cost of this is around 5.0 Tgas as of 2025-12-08
    let std_cost = execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_std_hash_map",
        json!({"elements": elements}),
    )
    .await;

    let expected_upper_bound = Gas::from_ggas(5 * elements.len() as u64 + 2000);
    assert!(
        std_cost < expected_upper_bound,
        "{std_cost} exceeded the expected value {expected_upper_bound}"
    );

    // The cost of this is around 247.1 Tgas as of 2025-12-08
    let near_cost = execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_near_hash_map",
        json!({"elements": elements}),
    )
    .await;

    let expected_upper_bound = Gas::from_ggas(250 * elements.len() as u64 + 2000);
    assert!(
        near_cost < expected_upper_bound,
        "{near_cost} exceeded the expected value {expected_upper_bound}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cost_of_update_in_map_std_vs_near() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await?;

    // The cost of this is around 1.9 Tgas as of 2025-12-08
    let std_cost = execute_transaction(
        &user_account,
        contract.id(),
        "update_from_std_hash_map",
        json!({"a": 2, "b": 5}),
    )
    .await;
    // The cost of this is around 2.2 Tgas as of 2025-12-08
    let near_cost = execute_transaction(
        &user_account,
        contract.id(),
        "update_from_near_hash_map",
        json!({"a": 2, "b": 5}),
    )
    .await;

    let expected_upper_bound = Gas::from_tgas(3);
    assert!(
        std_cost < expected_upper_bound,
        "{std_cost} exceeded the expected value {expected_upper_bound}"
    );
    assert!(
        near_cost < expected_upper_bound,
        "{near_cost} exceeded the expected value {expected_upper_bound}"
    );

    // Add 1000 elements to both maps
    let elements = (0..1000u32).map(|i| (i, 2 * i)).collect::<Vec<_>>();
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_std_hash_map",
        json!({"elements": elements}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_near_hash_map",
        json!({"elements": elements}),
    )
    .await;

    // The cost of this is around 3.6 Tgas as of 2025-12-08
    let std_cost = execute_transaction(
        &user_account,
        contract.id(),
        "update_from_std_hash_map",
        json!({"a": 2, "b": 5}),
    )
    .await;

    // The cost of this is around 2.1 Tgas as of 2025-12-08
    let near_cost = execute_transaction(
        &user_account,
        contract.id(),
        "update_from_near_hash_map",
        json!({"a": 2, "b": 5}),
    )
    .await;

    let expected_lower_bound = Gas::from_tgas(3);
    assert!(
        std_cost > expected_lower_bound,
        "{std_cost} did not exceed the expected value {expected_lower_bound}"
    );

    let expected_upper_bound = Gas::from_tgas(3);
    assert!(
        near_cost < expected_upper_bound,
        "{near_cost} exceeded the expected value {expected_upper_bound}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cost_of_remove_in_map_std_vs_near() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await?;

    let elements = (0..10u32).map(|i| (i, 2 * i)).collect::<Vec<_>>();
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_std_hash_map",
        json!({"elements": elements}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_near_hash_map",
        json!({"elements": elements}),
    )
    .await;

    // The cost of this is around 2.1 Tgas as of 2025-12-08
    let std_cost = execute_transaction(
        &user_account,
        contract.id(),
        "remove_from_std_hash_map",
        json!({"a": 2}),
    )
    .await;

    // The cost of this is around 2.7 Tgas as of 2025-12-08
    let near_cost = execute_transaction(
        &user_account,
        contract.id(),
        "remove_from_near_hash_map",
        json!({"a": 2}),
    )
    .await;

    let expected_upper_bound = Gas::from_tgas(3);
    assert!(
        std_cost < expected_upper_bound,
        "{std_cost} exceeded the expected value {expected_upper_bound}"
    );
    assert!(
        near_cost < expected_upper_bound,
        "{near_cost} exceeded the expected value {expected_upper_bound}"
    );

    // Add 1000 elements to both maps
    let elements = (0..1000u32).map(|i| (i, 2 * i)).collect::<Vec<_>>();
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_std_hash_map",
        json!({"elements": elements}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_near_hash_map",
        json!({"elements": elements}),
    )
    .await;

    // The cost of this is around 3.6 Tgas as of 2025-12-08
    let std_cost = execute_transaction(
        &user_account,
        contract.id(),
        "remove_from_std_hash_map",
        json!({"a": 2}),
    )
    .await;

    // The cost of this is around 2.8 Tgas as of 2025-12-08
    let near_cost = execute_transaction(
        &user_account,
        contract.id(),
        "remove_from_near_hash_map",
        json!({"a": 2}),
    )
    .await;

    let expected_lower_bound = Gas::from_tgas(3);
    assert!(
        std_cost > expected_lower_bound,
        "{std_cost} did not exceed the expected value {expected_lower_bound}"
    );

    let expected_upper_bound = Gas::from_tgas(3);
    assert!(
        near_cost < expected_upper_bound,
        "{near_cost} exceeded the expected value {expected_upper_bound}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cost_of_clear_in_map_std_vs_near() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await?;

    // If this is set to 1000, then we get error
    // FunctionCallError(ExecutionError("Size of the recorded trie storage proof has exceeded the allowed limit (4.0 MB)"))
    // when trying to clear the near hash map
    let elements = (0..100u32).map(|i| (i, 2 * i)).collect::<Vec<_>>();
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_std_hash_map",
        json!({"elements": elements}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "insert_many_near_hash_map",
        json!({"elements": elements}),
    )
    .await;

    // The cost of this is around 2.2 Tgas as of 2025-12-08
    let std_cost = execute_transaction(
        &user_account,
        contract.id(),
        "clear_std_hash_map",
        json!({}),
    )
    .await;

    // The cost of this is around 31.5 Tgas as of 2025-12-08
    let near_cost = execute_transaction(
        &user_account,
        contract.id(),
        "clear_near_hash_map",
        json!({}),
    )
    .await;

    let expected_upper_bound = Gas::from_tgas(3);
    assert!(
        std_cost < expected_upper_bound,
        "{std_cost} exceeded the expected value {expected_upper_bound}"
    );

    let expected_upper_bound = Gas::from_tgas(32);
    assert!(
        near_cost < expected_upper_bound,
        "{near_cost} exceeded the expected value {expected_upper_bound}"
    );

    Ok(())
}
