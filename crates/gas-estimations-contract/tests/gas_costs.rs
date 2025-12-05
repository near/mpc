#![allow(clippy::disallowed_types)]
use near_sdk::AccountId;
use near_workspaces::Account;
use serde_json::json;

async fn execute_transaction(
    user_account: &Account,
    contract_id: &AccountId,
    function: &str,
    args: serde_json::Value,
) {
    let outcome = user_account
        .call(contract_id, function)
        .args_json(args)
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    println!("function: {function} gas: {}", outcome.total_gas_burnt);
}

#[tokio::test]
async fn test_compare_gas_costs() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let user_account = sandbox.dev_create_account().await?;

    let elements = (0..100u32).map(|i| (i, vec![i; 1000])).collect::<Vec<_>>();

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
    execute_transaction(
        &user_account,
        contract.id(),
        "get_from_std_hash_map",
        json!({"element": 2}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "get_from_near_hash_map",
        json!({"element": 2}),
    )
    .await;

    execute_transaction(
        &user_account,
        contract.id(),
        "update_from_std_hash_map",
        json!({"a": 2, "b": elements[3].1}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "update_from_near_hash_map",
        json!({"a": 2, "b": elements[3].1}),
    )
    .await;

    execute_transaction(
        &user_account,
        contract.id(),
        "remove_from_std_hash_map",
        json!({"a": 2}),
    )
    .await;
    execute_transaction(
        &user_account,
        contract.id(),
        "remove_from_near_hash_map",
        json!({"a": 2}),
    )
    .await;

    Ok(())
}
