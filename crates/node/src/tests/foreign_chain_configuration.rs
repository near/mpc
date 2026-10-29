use crate::p2p::testing::port_seed;
use crate::tests::{DEFAULT_BLOCK_TIME, IntegrationTestSetup, wait_for_registrations};
use crate::tracking::AutoAbortTask;
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, DomainConfig, DomainId, DomainPurpose, ForeignChain,
    Protocol, ProviderConfig, ProviderId, ReconstructionThreshold,
};
use near_time::Clock;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn foreign_chain_configuration_auto_registered_to_contract_on_startup__should_use_local_config()
 {
    // Given
    const GOVERNANCE_THRESHOLD: usize = 2;
    const RECONSTRUCTION_THRESHOLD: usize = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;

    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        vec!["test0".parse().unwrap(), "test1".parse().unwrap()],
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::FOREIGN_CHAIN_POLICY_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let providers = NonEmptyBTreeMap::new(
        RpcProviderName::from(PROVIDER.to_string()),
        ForeignChainProviderConfig {
            rpc_url: PROVIDER_URL.to_string(),
            auth: AuthConfig::None,
        },
    );

    let foreign_chains = ForeignChainsConfig {
        solana: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            expected_network_fingerprint: None,
            providers,
        }),
        bitcoin: None,
        ethereum: None,
        abstract_chain: None,
        starknet: None,
        bnb: None,
        base: None,
        arbitrum: None,
        hyper_evm: None,
        polygon: None,
        aptos: None,
        sui: None,
        avalanche: None,
        adi: None,
        fogo: None,
        rpc_preset: None,
        credentials: Default::default(),
    };
    for config in &mut setup.configs {
        config.config.foreign_chains = foreign_chains.clone();
    }

    let expected_foreign_chains: BTreeSet<ForeignChain> = foreign_chains
        .iter_chains()
        .map(|(chain, _)| chain)
        .collect();

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        // Availability is computed based on ForeignTx domains threshold.
        contract.add_domains(vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(RECONSTRUCTION_THRESHOLD as u64),
            purpose: DomainPurpose::ForeignTx,
        }]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // When
    let node_count = setup.participants.participants.len();
    wait_for_registrations(&setup.indexer, node_count, &BTreeSet::new()).await;

    // Then
    {
        let mut contract = setup.indexer.contract_mut().await;
        assert!(contract.available_foreign_chains().is_empty());
        contract.whitelist_foreign_chain_providers(solana_whitelist());
    }
    wait_for_registrations(&setup.indexer, node_count, &expected_foreign_chains).await;
    let contract = setup.indexer.contract_mut().await;
    assert_eq!(
        **contract.available_foreign_chains(),
        expected_foreign_chains
    );
}

const PROVIDER: &str = "public";
const PROVIDER_URL: &str = "https://rpc.public.example.com";

fn solana_whitelist() -> BTreeMap<ForeignChain, ChainEntry> {
    BTreeMap::from([(
        ForeignChain::Solana,
        ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId(PROVIDER.to_string()),
                ProviderConfig {
                    base_url: PROVIDER_URL.to_string(),
                    auth_scheme: AuthScheme::None,
                    chain_routing: ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        },
    )])
}
