use contract_interface::method_names;
use mpc_contract::primitives::domain::SignatureScheme;
use near_sdk::{CurveType, PublicKey};
use serde_json::json;
use std::str::FromStr;

use crate::sandbox::{
    common::{init_env, SandboxTestSetup},
    utils::consts::PARTICIPANT_LEN,
};

#[tokio::test]
async fn test_key_version() -> anyhow::Result<()> {
    let SandboxTestSetup { contract, .. } =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

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
    let SandboxTestSetup { contract, .. } =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

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
    let SandboxTestSetup { contract, .. } =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;

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
