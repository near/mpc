use crate::p2p::testing::PortSeed;
use crate::tests::{IntegrationTestSetup, DEFAULT_BLOCK_TIME};
use crate::tracking::AutoAbortTask;
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_contract_interface::types::{ForeignChain, RpcProvider};
use near_time::Clock;
use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::time::Duration;

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn foreign_chain_configuration_auto_registered_to_contract_on_startup__should_use_local_config(
) {
    // Given
    const THRESHOLD: usize = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;

    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        vec!["test0".parse().unwrap(), "test1".parse().unwrap()],
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::FOREIGN_CHAIN_POLICY_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let providers = near_mpc_bounded_collections::NonEmptyBTreeMap::new(
        RpcProviderName::from("public".to_string()),
        ForeignChainProviderConfig {
            rpc_url: "https://rpc.public.example.com".parse().unwrap(),
            auth: AuthConfig::None,
        },
    );

    let foreign_chains = ForeignChainsConfig {
        solana: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers,
        }),
        bitcoin: None,
        ethereum: None,
        abstract_chain: None,
        starknet: None,
        bnb: None,
        base: None,
    };
    for config in &mut setup.configs {
        config.config.foreign_chains = foreign_chains.clone();
    }

    let expected_foreign_chains: BTreeSet<ForeignChain> =
        foreign_chains.configured_chains().keys().copied().collect();

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // When
    let wait_result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            {
                let contract = setup.indexer.contract_mut().await;
                if **contract.supported_foreign_chains() == expected_foreign_chains {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    // Then
    assert!(wait_result.is_ok(), "timed out waiting for policy update");
    let contract = setup.indexer.contract_mut().await;

    assert_eq!(
        **contract.supported_foreign_chains(),
        expected_foreign_chains
    );

    let expected_node_support = BTreeSet::from([ForeignChain::Solana]);

    let all_nodes_submitted_supported_chains = contract
        .supported_foreign_chains_by_node()
        .values()
        .all(|node_support| **node_support == expected_node_support);

    assert!(all_nodes_submitted_supported_chains);
}
