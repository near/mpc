use std::collections::BTreeSet;
use std::num::NonZeroU64;

use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, ForeignChain, Protocol, ReconstructionThreshold,
    SupportedForeignChains,
};

const SOLANA_PROVIDER_NAME: &str = "public";
const SOLANA_RPC_URL: &str = "https://rpc.public.example.com";

fn solana_foreign_chains_config() -> ForeignChainsConfig {
    ForeignChainsConfig {
        solana: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                SOLANA_PROVIDER_NAME.to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: SOLANA_RPC_URL.to_string(),
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

fn solana_foreign_chain_support_dto() -> SupportedForeignChains {
    BTreeSet::from([(ForeignChain::Solana)]).into()
}

/// Verify that a chain is only reported as supported once every active
/// participant has registered a configuration that includes it.
///
/// 3-node cluster: nodes 0 and 1 are configured with Solana foreign chain,
/// node 2 has no foreign chain config.
///
/// 1. All three nodes auto-register on startup — nodes 0 and 1 with Solana,
///    node 2 with an empty configuration. Solana should NOT yet be in the
///    supported-chains set (node 2 does not include it).
/// 2. After node 2 manually registers Solana, the chain is reported as supported.
#[tokio::test]
#[expect(non_snake_case)]
async fn supported_foreign_chains__should_require_all_participants_to_register() {
    // given — 3-node cluster with foreign chains on nodes 0 and 1 only
    let (cluster, _running) =
        common::must_setup_cluster(common::FOREIGN_CHAIN_POLICY_PORT_SEED, |c| {
            c.node_foreign_chains_configs = vec![
                solana_foreign_chains_config(), // node 0
                solana_foreign_chains_config(), // node 1
                ForeignChainsConfig::default(), // node 2 — no foreign chains
            ];
        })
        .await;

    // when — wait for all three nodes to register (one with an empty configuration)
    // without Solana becoming supported
    (|| async {
        let registrations = cluster
            .view_foreign_chain_configurations()
            .await
            .expect("failed to view configurations");
        let supported = cluster
            .view_foreign_chains_supported_by_contract()
            .await
            .expect("failed to view supported chains");

        let configurations = &registrations.foreign_chain_support_by_node;
        anyhow::ensure!(
            configurations.len() == 3,
            "expected exactly 3 registrations, got {}",
            configurations.len()
        );
        let empty_registrations = configurations.values().filter(|c| c.is_empty()).count();
        anyhow::ensure!(
            empty_registrations == 1,
            "expected exactly 1 empty registration (node 2), got {empty_registrations}"
        );
        anyhow::ensure!(
            !supported.contains(&ForeignChain::Solana),
            "Solana should not be supported before all participants register it"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for all three registrations with one empty");

    // when — node 2 registers Solana directly on the contract.
    let outcome = cluster
        .register_foreign_chain_config(2, &solana_foreign_chain_support_dto())
        .await
        .expect("failed to register foreign chain config from node 2");
    assert!(
        outcome.is_success(),
        "register_foreign_chain_config failed: {:?}",
        outcome.failure_message()
    );

    // then — Solana becomes supported once every participant has registered it
    (|| async {
        let supported = cluster
            .view_foreign_chains_supported_by_contract()
            .await
            .expect("failed to view supported chains");

        anyhow::ensure!(
            supported.contains(&ForeignChain::Solana),
            "Solana should be supported after all participants register it"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for Solana to be reported as supported");
}

/// Verify that a chain becomes available only once it is whitelisted and a
/// signing threshold of participants has registered a config covering it.
///
/// 3-node cluster (ForeignTx domain threshold 2): nodes 0 and 1 are configured
/// with the Solana foreign chain, node 2 has no foreign chain config.
///
/// 1. All three nodes auto-register on startup — nodes 0 and 1 with Solana,
///    node 2 with an empty configuration. Solana must NOT be available while
///    it is not whitelisted.
/// 2. After the participants whitelist Solana, two registrations reach the
///    threshold and the chain becomes available — node 2's foreign-chain-config
///    registration is not required (it still votes for the whitelist).
#[tokio::test]
#[expect(non_snake_case)]
async fn available_foreign_chains__should_require_whitelist_and_threshold_of_registrations() {
    // given — 3-node cluster with a ForeignTx domain; Solana configured on
    // nodes 0 and 1 only, and no chain whitelisted yet.
    let (cluster, _running) =
        common::must_setup_cluster(common::AVAILABLE_FOREIGN_CHAINS_PORT_SEED, |c| {
            c.domains = vec![DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::ForeignTx,
            }];
            c.node_foreign_chains_configs = vec![
                solana_foreign_chains_config(), // node 0
                solana_foreign_chains_config(), // node 1
                ForeignChainsConfig::default(), // node 2 — no foreign chains
            ];
        })
        .await;

    // when — wait for all three nodes to register (one with an empty
    // configuration) without Solana becoming available.
    (|| async {
        let registrations = cluster
            .view_foreign_chains_configs()
            .await
            .expect("failed to view registered configs");
        let available = cluster
            .view_available_foreign_chains()
            .await
            .expect("failed to view available chains");

        anyhow::ensure!(
            registrations.len() == 3,
            "expected exactly 3 registrations, got {}",
            registrations.len()
        );
        let empty_registrations = registrations.values().filter(|c| c.is_empty()).count();
        anyhow::ensure!(
            empty_registrations == 1,
            "expected exactly 1 empty registration (node 2), got {empty_registrations}"
        );
        anyhow::ensure!(
            !available.contains(&ForeignChain::Solana),
            "Solana must not be available before it is whitelisted"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for all three registrations with one empty");

    // when — the participants whitelist Solana.
    cluster
        .whitelist_foreign_chains(&[0, 1, 2], &BTreeSet::from([ForeignChain::Solana]))
        .await
        .expect("failed to whitelist Solana");

    // then — Solana becomes available with two of three registrations.
    (|| async {
        let available = cluster
            .view_available_foreign_chains()
            .await
            .expect("failed to view available chains");

        anyhow::ensure!(
            available.contains(&ForeignChain::Solana),
            "Solana should be available once whitelisted and registered by a threshold of nodes"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for Solana to become available");
}
