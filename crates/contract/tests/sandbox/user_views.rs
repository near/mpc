use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ForeignChain, Protocol, ProviderConfig, ProviderId,
};
use near_sdk::borsh;
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
async fn vote_update_foreign_chain_providers__should_apply_chain_state_after_threshold(
) -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let proposed_id = ProviderId("alchemy".to_string());
    let proposed_config = ProviderConfig {
        base_url: "https://eth-mainnet.g.alchemy.com/v2/".to_string(),
        auth_scheme: AuthScheme::None,
        chain_routing: ChainRouting::Embedded,
    };
    let votes = NonEmptyBTreeMap::new(
        ForeignChain::Ethereum,
        ChainEntry {
            providers: NonEmptyBTreeMap::new(proposed_id.clone(), proposed_config.clone()),
            quorum: 1,
        },
    );

    // Entry-point args are borsh-encoded.
    let args = borsh::to_vec(&votes)?;
    // Gating matches the protocol signing threshold (`self.threshold()?.value()` in
    // the contract). Sandbox setup uses 10 participants with a 60% threshold = 6.
    // First 5 votes — should not yet apply.
    for (i, account) in mpc_signer_accounts.iter().take(5).enumerate() {
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
            "vote_update_foreign_chain_providers (vote {}) failed: {result:?}",
            i + 1,
        );
    }

    // Sanity check: nothing applied yet (only 5 of 6 threshold votes cast).
    let whitelist_before: BTreeMap<ForeignChain, ChainEntry> = contract
        .view(method_names::ALLOWED_FOREIGN_CHAIN_PROVIDERS)
        .args_json(json!({}))
        .await?
        .borsh()?;
    assert!(
        whitelist_before.is_empty(),
        "chain should not be applied yet (only 5 of 6 threshold votes cast)"
    );

    // 6th vote — crosses the threshold and applies the chain.
    let result = mpc_signer_accounts[5]
        .call(
            contract.id(),
            method_names::VOTE_UPDATE_FOREIGN_CHAIN_PROVIDERS,
        )
        .args(args.clone())
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "vote_update_foreign_chain_providers (vote 6) failed: {result:?}"
    );

    // Then: chain entry is applied (result is borsh-encoded — see the view fn's doc).
    let whitelist: BTreeMap<ForeignChain, ChainEntry> = contract
        .view(method_names::ALLOWED_FOREIGN_CHAIN_PROVIDERS)
        .args_json(json!({}))
        .await?
        .borsh()?;
    let stored = whitelist
        .get(&ForeignChain::Ethereum)
        .expect("Ethereum entry should be present after 6 matching votes");
    assert_eq!(stored.providers.len(), 1);
    assert_eq!(stored.providers.get(&proposed_id), Some(&proposed_config));
    assert_eq!(stored.quorum, 1);

    Ok(())
}
