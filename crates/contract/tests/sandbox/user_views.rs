use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{ForeignChain, Protocol, ProviderEntry};
use near_sdk::{CurveType, PublicKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;

use crate::sandbox::common::SandboxTestSetup;

#[tokio::test]
async fn test_key_version() -> anyhow::Result<()> {
    let SandboxTestSetup { contract, .. } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let version: u32 = contract
        .view(method_names::LATEST_KEY_VERSION)
        .args_json(json!({}))
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(version, 0);
    Ok(())
}

#[tokio::test]
async fn test_public_key() -> anyhow::Result<()> {
    let SandboxTestSetup { contract, .. } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let key: String = contract
        .view(method_names::PUBLIC_KEY)
        .args_json(json!({}))
        .await
        .unwrap()
        .json()
        .unwrap();
    println!("{:?}", key);
    let pk = PublicKey::from_str(&key)?;
    assert_eq!(pk.curve_type(), CurveType::SECP256K1);
    Ok(())
}

#[tokio::test]
async fn test_derived_public_key() -> anyhow::Result<()> {
    let SandboxTestSetup { contract, .. } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let key: String = contract
        .view(method_names::DERIVED_PUBLIC_KEY)
        .args_json(json!({
            "path": "test",
            "predecessor": "alice.near"
        }))
        .await
        .unwrap()
        .json()
        .unwrap();
    let pk = PublicKey::from_str(&key)?;
    assert_eq!(pk.curve_type(), CurveType::SECP256K1);
    Ok(())
}

#[tokio::test]
#[expect(non_snake_case)]
async fn allowed_foreign_chain_providers_view__should_start_empty() -> anyhow::Result<()> {
    // Given a freshly deployed contract — the whitelist has no votes applied yet.
    let SandboxTestSetup { contract, .. } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    // When
    let providers: BTreeMap<ForeignChain, Vec<ProviderEntry>> = contract
        .view(method_names::ALLOWED_FOREIGN_CHAIN_PROVIDERS)
        .args_json(json!({}))
        .await
        .unwrap()
        .json()
        .unwrap();

    // Then
    assert!(
        providers.is_empty(),
        "expected empty whitelist on fresh contract, got: {providers:?}",
    );
    Ok(())
}

