#![allow(non_snake_case)]

use crate::sandbox::common::SandboxTestSetup;
use crate::sandbox::utils::consts::ALL_CURVES;
use assert_matches::assert_matches;
use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_mpc_contract_interface::method_names::REGISTER_FOREIGN_CHAIN_SUPPORT;
use near_mpc_contract_interface::types as dtos;
use rstest::rstest;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[expect(deprecated)]
use near_mpc_contract_interface::method_names::REGISTER_FOREIGN_CHAIN_CONFIG;

#[rstest]
#[expect(deprecated)]
#[case(REGISTER_FOREIGN_CHAIN_CONFIG,
        json!({
            "foreign_chain_configuration": dtos::ForeignChainConfiguration::from(BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://btc.example.com".to_string(),
                    }),
                ),
                (
                    dtos::ForeignChain::Starknet,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://starknet.example.com".to_string(),
                    }),
                ),
            ]))
        })
    )]
#[case(REGISTER_FOREIGN_CHAIN_SUPPORT,
        json!({
            "foreign_chain_support": dtos::SupportedForeignChains::from(BTreeSet::from([
                dtos::ForeignChain::Bitcoin,
                dtos::ForeignChain::Starknet,
            ]))
        })
    )]
#[tokio::test]
async fn register_foreign_chain_support__stores_and_returns_supported_chains(
    #[case] method_name: &str,
    #[case] payload: serde_json::Value,
) {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_curves(ALL_CURVES)
        .build()
        .await;

    for account in &mpc_signer_accounts {
        let result = account
            .call(contract.id(), method_name)
            .args_json(payload.clone())
            .transact()
            .await
            .unwrap()
            .into_result();

        assert_matches!(result, Ok(_), "register should succeed for participant");
    }

    // Then: get_supported_foreign_chains returns the registered chains
    let supported: Vec<String> = contract
        .view("get_supported_foreign_chains")
        .await
        .unwrap()
        .json()
        .unwrap();
    let mut supported_sorted = supported.clone();
    supported_sorted.sort();
    assert_eq!(
        supported_sorted,
        vec!["Bitcoin", "Starknet"],
        "all registered chains should be returned when all participants support them"
    );
}

#[rstest]
#[expect(deprecated)]
#[case(REGISTER_FOREIGN_CHAIN_CONFIG,
        json!({
            "foreign_chain_configuration": dtos::ForeignChainConfiguration::from(BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://btc.example.com".to_string(),
                    }),
                ),
                (
                    dtos::ForeignChain::Starknet,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://starknet.example.com".to_string(),
                    }),
                ),
            ]))
        }),
        json!({
            "foreign_chain_configuration": dtos::ForeignChainConfiguration::from(BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://btc.example.com".to_string(),
                    }),
                ),
            ]))
        })

    )]
#[case(REGISTER_FOREIGN_CHAIN_SUPPORT,
        json!({
            "foreign_chain_support": dtos::SupportedForeignChains::from(BTreeSet::from([
                dtos::ForeignChain::Bitcoin,
                dtos::ForeignChain::Starknet,
            ]))
        }),
        json!({
            "foreign_chain_support": dtos::SupportedForeignChains::from(BTreeSet::from([
                dtos::ForeignChain::Bitcoin,
            ]))
        })
    )]
#[tokio::test]
async fn register_foreign_chain_config__excludes_chains_not_supported_by_all(
    #[case] method_name: &str,
    #[case] bitcoin_and_starknet: serde_json::Value,
    #[case] bitcoin_only: serde_json::Value,
) {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_curves(ALL_CURVES)
        .build()
        .await;

    // When: first participant registers Bitcoin + Starknet
    let result = mpc_signer_accounts[0]
        .call(contract.id(), method_name)
        .args_json(bitcoin_and_starknet)
        .transact()
        .await
        .unwrap()
        .into_result();
    assert_matches!(result, Ok(_));

    // And: remaining participants register only Bitcoin
    for account in &mpc_signer_accounts[1..] {
        let result = account
            .call(contract.id(), method_name)
            .args_json(bitcoin_only.clone())
            .transact()
            .await
            .unwrap()
            .into_result();
        assert_matches!(result, Ok(_));
    }

    // Then: only Bitcoin is in the supported set (Starknet is not unanimous)
    let supported: Vec<String> = contract
        .view("get_supported_foreign_chains")
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        supported,
        vec!["Bitcoin"],
        "only chains supported by ALL participants should be returned"
    );
}

#[rstest]
#[expect(deprecated)]
#[case(REGISTER_FOREIGN_CHAIN_CONFIG,
        json!({
            "foreign_chain_configuration": dtos::ForeignChainConfiguration::from(BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://btc.example.com".to_string(),
                    }),
                ),
            ]))
        })
    )]
#[case(REGISTER_FOREIGN_CHAIN_SUPPORT,
        json!({
            "foreign_chain_support": dtos::SupportedForeignChains::from(BTreeSet::from([
                dtos::ForeignChain::Bitcoin,
            ]))
        })
    )]
#[tokio::test]
async fn register_foreign_chain_config__returns_empty_when_not_all_registered(
    #[case] method_name: &str,
    #[case] bitcoin_only: serde_json::Value,
) {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_curves(ALL_CURVES)
        .build()
        .await;

    // When: only one participant registers
    let result = mpc_signer_accounts[0]
        .call(contract.id(), method_name)
        .args_json(bitcoin_only.clone())
        .transact()
        .await
        .unwrap()
        .into_result();
    assert_matches!(result, Ok(_));

    // Then: get_supported_foreign_chains returns empty (not all participants registered)
    let supported: Vec<String> = contract
        .view("get_supported_foreign_chains")
        .await
        .unwrap()
        .json()
        .unwrap();
    assert!(
        supported.is_empty(),
        "should be empty when not all participants have registered"
    );
}
