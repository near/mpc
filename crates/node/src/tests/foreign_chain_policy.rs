use crate::config::{
    AuthConfig, ForeignChainsConfig, SolanaApiVariant, SolanaChainConfig, SolanaProviderConfig,
};
use crate::p2p::testing::PortSeed;
use crate::tests::{IntegrationTestSetup, DEFAULT_BLOCK_TIME};
use crate::tracking::AutoAbortTask;
use near_time::Clock;
use std::time::Duration;

#[tokio::test]
#[test_log::test]
#[allow(non_snake_case)]
async fn foreign_chain_policy_auto_vote_on_startup__should_apply_local_policy() {
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

    let providers = non_empty_collections::NonEmptyBTreeMap::new(
        "public".to_string(),
        SolanaProviderConfig {
            rpc_url: "https://rpc.public.example.com".to_string(),
            api_variant: SolanaApiVariant::Standard,
            auth: AuthConfig::None,
        },
    );

    let foreign_chains = ForeignChainsConfig {
        solana: Some(SolanaChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers,
        }),
        bitcoin: None,
        ethereum: None,
        abstract_chain: None,
        starknet: None,
    };
    for config in &mut setup.configs {
        config.config.foreign_chains = foreign_chains.clone();
    }

    let expected_policy = foreign_chains
        .to_policy()
        .expect("policy should not be None");

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
                if contract.foreign_chain_policy() == &expected_policy {
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
    assert_eq!(contract.foreign_chain_policy(), &expected_policy);
    assert!(contract
        .foreign_chain_policy_votes()
        .proposal_by_account
        .is_empty());
}
