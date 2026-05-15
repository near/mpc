use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainRouting, ForeignChain, Protocol, ProviderEntry, ProviderVoteAction,
};
use near_sdk::borsh;
use near_sdk::{CurveType, PublicKey};
use serde_json::json;
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
async fn vote_update_foreign_chain_providers__should_succeed_for_authenticated_voters(
) -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let actions = vec![ProviderVoteAction::Add {
        chain: ForeignChain::Ethereum,
        entry: ProviderEntry {
            provider_id: "alchemy".to_string(),
            base_url: "https://eth-mainnet.g.alchemy.com/v2/".to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        },
    }];

    // Entry-point args are borsh-encoded — see the entry point's doc comment for why.
    let args = borsh::to_vec(&actions)?;
    // Default per-chain threshold is 2 — two distinct signers casting the same batch.
    for account in mpc_signer_accounts.iter().take(2) {
        let result = account
            .call(
                contract.id(),
                method_names::VOTE_UPDATE_FOREIGN_CHAIN_PROVIDERS,
            )
            .args(args.clone())
            .transact()
            .await?;
        assert!(
            result.is_success(),
            "vote_update_foreign_chain_providers failed: {result:?}",
        );
    }
    Ok(())
}
