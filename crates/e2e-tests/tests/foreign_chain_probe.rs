use std::collections::BTreeMap;
use std::num::NonZeroU64;

use crate::common;

use e2e_tests::foreign_chain_mock::setup_evm_chain_id_mock;
use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use httpmock::MockServer;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};

/// Belongs to no real chain: the probe only compares what a provider answers against config.
const EXPECTED_NETWORK: u64 = 99999;
/// Any chain id the expected mock does not serve, so the probe reads a network mismatch.
const ANOTHER_NETWORK: u64 = 1;

fn bnb_chain_config(providers: &[(&str, &str)]) -> ForeignChainsConfig {
    let providers: BTreeMap<_, _> = providers
        .iter()
        .map(|(name, rpc_url)| {
            (
                name.to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: rpc_url.to_string(),
                    auth: AuthConfig::None,
                },
            )
        })
        .collect();
    ForeignChainsConfig {
        bnb: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(10).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_network_fingerprint: Some(EXPECTED_NETWORK.to_string()),
            providers: providers.try_into().expect("a named provider"),
        }),
        ..Default::default()
    }
}

/// Both nodes expect the same network and configure two BNB providers, so the healthy gauge
/// separates them on one provider serving another network.
#[tokio::test]
#[expect(non_snake_case)]
async fn foreign_chain_probe__should_publish_provider_health_on_startup() {
    // Given
    let expected_network = MockServer::start();
    setup_evm_chain_id_mock(&expected_network, EXPECTED_NETWORK);
    let other_network = MockServer::start();
    setup_evm_chain_id_mock(&other_network, ANOTHER_NETWORK);

    // The config rejects duplicate provider URLs, so the two sound providers take separate paths.
    let good_path = expected_network.url("/good_provider");
    let also_good_path = expected_network.url("/also_good_provider");
    let wrong_network = other_network.url("/wrong_network_provider");

    // When
    let (cluster, _running) = common::must_setup_cluster(
        common::FOREIGN_CHAIN_PROBE_PORT_SEED,
        |c: &mut e2e_tests::MpcClusterConfig| {
            c.num_nodes = 2;
            c.threshold = 2;
            c.foreign_chains.node_configs = vec![
                bnb_chain_config(&[
                    ("good_provider", &good_path),
                    ("also_good_provider", &also_good_path),
                ]),
                bnb_chain_config(&[
                    ("good_provider", &good_path),
                    ("wrong_network_provider", &wrong_network),
                ]),
            ];
        },
    )
    .await;

    // Then
    common::wait_metric_on_nodes(
        &cluster,
        &[0, 1],
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED,
        |value| value == 2,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("both nodes should report two configured BNB providers");

    common::wait_metric_on_nodes(
        &cluster,
        &[0],
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY,
        |value| value == 2,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("both providers serving the expected network should be healthy");

    common::wait_metric_on_nodes(
        &cluster,
        &[1],
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY,
        |value| value == 1,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("only the provider serving the expected network should be healthy");
}
