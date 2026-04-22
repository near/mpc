#![allow(non_snake_case)]

use crate::sandbox::common::SandboxTestSetup;
use crate::sandbox::utils::consts::ALL_CURVES;
use assert_matches::assert_matches;
use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_mpc_contract_interface::method_names::REGISTER_FOREIGN_CHAIN_CONFIG;
use near_mpc_contract_interface::types as dtos;
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn register_foreign_chain_config__stores_and_returns_supported_chains() {
    // Given: a running contract with participants
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_curves(ALL_CURVES)
        .build()
        .await;

    // When: ALL participants register the same supported chains
    let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
        (
            dtos::ForeignChain::Bitcoin,
            NonEmptyBTreeSet::new(dtos::RpcProvider {
                rpc_url: "https://btc.example.com".to_string(),
                name: "standard".to_string(),
            }),
        ),
        (
            dtos::ForeignChain::Starknet,
            NonEmptyBTreeSet::new(dtos::RpcProvider {
                rpc_url: "https://starknet.example.com".to_string(),
                name: "standard".to_string(),
            }),
        ),
    ])
    .into();

    for account in &mpc_signer_accounts {
        let result = account
            .call(contract.id(), REGISTER_FOREIGN_CHAIN_CONFIG)
            .args_json(json!({
                "foreign_chain_configuration": foreign_chain_configuration
            }))
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

#[tokio::test]
async fn register_foreign_chain_config__excludes_chains_not_supported_by_all() {
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
    let bitcoin_and_starknet: dtos::ForeignChainConfiguration = BTreeMap::from([
        (
            dtos::ForeignChain::Bitcoin,
            NonEmptyBTreeSet::new(dtos::RpcProvider {
                rpc_url: "https://btc.example.com".to_string(),
                name: "standard".to_string(),
            }),
        ),
        (
            dtos::ForeignChain::Starknet,
            NonEmptyBTreeSet::new(dtos::RpcProvider {
                rpc_url: "https://starknet.example.com".to_string(),
                name: "standard".to_string(),
            }),
        ),
    ])
    .into();

    let result = mpc_signer_accounts[0]
        .call(contract.id(), REGISTER_FOREIGN_CHAIN_CONFIG)
        .args_json(json!({
            "foreign_chain_configuration": bitcoin_and_starknet
        }))
        .transact()
        .await
        .unwrap()
        .into_result();
    assert_matches!(result, Ok(_));

    // And: remaining participants register only Bitcoin
    let bitcoin_only: dtos::ForeignChainConfiguration = BTreeMap::from([(
        dtos::ForeignChain::Bitcoin,
        NonEmptyBTreeSet::new(dtos::RpcProvider {
            rpc_url: "https://btc.example.com".to_string(),
            name: "standard".to_string(),
        }),
    )])
    .into();

    for account in &mpc_signer_accounts[1..] {
        let result = account
            .call(contract.id(), REGISTER_FOREIGN_CHAIN_CONFIG)
            .args_json(json!({
                "foreign_chain_configuration": bitcoin_only
            }))
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

#[tokio::test]
async fn register_foreign_chain_config__returns_empty_when_not_all_registered() {
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
    let bitcoin_only: dtos::ForeignChainConfiguration = BTreeMap::from([(
        dtos::ForeignChain::Bitcoin,
        NonEmptyBTreeSet::new(dtos::RpcProvider {
            rpc_url: "https://btc.example.com".to_string(),
            name: "standard".to_string(),
        }),
    )])
    .into();

    let result = mpc_signer_accounts[0]
        .call(contract.id(), REGISTER_FOREIGN_CHAIN_CONFIG)
        .args_json(json!({
            "foreign_chain_configuration": bitcoin_only
        }))
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
