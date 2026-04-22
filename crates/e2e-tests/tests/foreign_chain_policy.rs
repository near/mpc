use std::collections::BTreeMap;
use std::num::NonZeroU64;

use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};
use near_mpc_contract_interface::types::{ForeignChain, ForeignChainConfiguration, RpcProvider};

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

fn solana_foreign_chain_configuration_dto() -> ForeignChainConfiguration {
    BTreeMap::from([(
        ForeignChain::Solana,
        NonEmptyBTreeSet::new(RpcProvider {
            rpc_url: SOLANA_RPC_URL.to_string(),
        }),
    )])
    .into()
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
    let (cluster, _running) = common::setup_cluster(common::FOREIGN_CHAIN_POLICY_PORT_SEED, |c| {
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

        let configurations = &registrations.foreign_chain_configuration_by_node;
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
        .register_foreign_chain_config(2, &solana_foreign_chain_configuration_dto())
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
