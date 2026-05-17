use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainRouting, ChainVote, ForeignChain, Protocol, ProviderEntry,
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

    let votes = vec![ChainVote {
        chain: ForeignChain::Ethereum,
        providers: vec![ProviderEntry {
            provider_id: "alchemy".to_string(),
            base_url: "https://eth-mainnet.g.alchemy.com/v2/".to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }],
        threshold: 1,
    }];

    // Entry-point args are borsh-encoded.
    let args = borsh::to_vec(&votes)?;
    // Gating matches the protocol signing threshold (`self.threshold()?.value()` in
    // the contract). Sandbox setup uses 10 participants with a 60% threshold = 6.
    for account in mpc_signer_accounts.iter().take(6) {
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
