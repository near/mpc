use std::num::NonZeroU64;

use crate::common;

use e2e_tests::foreign_chain_mock::{MOCK_EVM_CHAIN_ID, MockAuthExpectation, setup_evm_mock};
use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use httpmock::MockServer;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;

const HEALTHY_PROVIDER: &str = "healthy";
const WRONG_NETWORK_PROVIDER: &str = "wrong-network";
/// Any chain id the mock does not serve, so the probe reads a network mismatch.
const ANOTHER_NETWORK: &str = "1";

fn base_config(rpc_url: &str, expected: &str, provider: &str) -> ForeignChainConfig {
    ForeignChainConfig {
        timeout_sec: NonZeroU64::new(10).unwrap(),
        max_retries: NonZeroU64::new(1).unwrap(),
        expected_network_fingerprint: Some(expected.to_string()),
        providers: NonEmptyBTreeMap::new(
            provider.to_string().into(),
            ForeignChainProviderConfig {
                rpc_url: rpc_url.to_string(),
                auth: AuthConfig::None,
            },
        ),
    }
}

/// The startup probe asks each configured provider for its chain id and publishes the per-chain
/// counts. Node 0 is pointed at a mock serving [`MOCK_EVM_CHAIN_ID`] and told to expect it, so its
/// provider is healthy; node 1 is told to expect a different network, so its provider is not.
/// Both configure one provider, so `configured` is 1 either way and only `healthy` separates them.
#[tokio::test]
#[expect(non_snake_case)]
async fn foreign_chain_probe__should_publish_provider_health_on_startup() {
    // given
    let server = MockServer::start();
    setup_evm_mock(&server, MockAuthExpectation::None);
    let url = server.url("/");

    let (cluster, _running) =
        common::must_setup_cluster(common::FOREIGN_CHAIN_PROBE_PORT_SEED, |c| {
            c.num_nodes = 2;
            c.threshold = 2;
            c.foreign_chains.node_configs = vec![
                ForeignChainsConfig {
                    base: Some(base_config(&url, MOCK_EVM_CHAIN_ID, HEALTHY_PROVIDER)),
                    ..Default::default()
                },
                ForeignChainsConfig {
                    base: Some(base_config(&url, ANOTHER_NETWORK, WRONG_NETWORK_PROVIDER)),
                    ..Default::default()
                },
            ];
        })
        .await;

    // when — the probe runs detached at startup, so both gauges settle on their own.
    common::wait_metric_on_nodes(
        &cluster,
        &[0, 1],
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED,
        |value| value == 1,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("both nodes should report one configured Base provider");

    // then
    common::wait_metric_on_nodes(
        &cluster,
        &[0],
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY,
        |value| value == 1,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("the provider serving the expected network should be healthy");

    let healthy = cluster
        .get_metric_all_nodes(metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY)
        .await
        .expect("failed to scrape metrics");
    assert_eq!(
        healthy[1],
        Some(0),
        "the provider serving another network should not be healthy"
    );
}
