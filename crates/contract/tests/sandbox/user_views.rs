use mpc_contract::primitives::domain::SignatureScheme;
use near_sdk::{CurveType, PublicKey};
use serde_json::json;
use std::str::FromStr;

use crate::sandbox::common::init_env;

#[tokio::test]
async fn test_key_version() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env(&[SignatureScheme::Secp256k1]).await;

    let version: u32 = contract
        .view("latest_key_version")
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
    let (_, contract, _, _) = init_env(&[SignatureScheme::Secp256k1]).await;

    let key: String = contract
        .view("public_key")
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
    let (_, contract, _, _) = init_env(&[SignatureScheme::Secp256k1]).await;

    let key: String = contract
        .view("derived_public_key")
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
