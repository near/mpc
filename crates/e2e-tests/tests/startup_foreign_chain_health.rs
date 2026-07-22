use std::num::NonZeroU64;
use std::time::Duration;

use crate::common;

use e2e_tests::MpcNodeState;
use e2e_tests::foreign_chain_mock::{
    MOCK_BLOCK_HASH, MOCK_TX_ID, MockAuthExpectation, MockServerExt, setup_evm_mock_with_block_hash,
};
use e2e_tests::metrics;
use e2e_tests::mpc_node::MpcNodeSetup;
use httpmock::MockServer;
use mpc_node_config::{
    BlockHashGolden, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
    HealthCheckGoldenConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;

const LOG_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

fn provider(rpc_url: String) -> ForeignChainProviderConfig {
    ForeignChainProviderConfig {
        rpc_url,
        auth: Default::default(),
    }
}

fn node_setup(cluster: &e2e_tests::MpcCluster, idx: usize) -> &MpcNodeSetup {
    match &cluster.nodes[idx] {
        MpcNodeState::Running(node) => node.setup(),
        MpcNodeState::Stopped(setup) => setup,
    }
}

/// The startup foreign-chain health check runs on the real mpc-node startup
/// path, probing each node's configured providers against test-supplied golden.
///
/// Node 0 (two `base` providers + golden) must pass one and fail the other;
/// node 1 (a provider, no golden) must skip on this local chain.
#[tokio::test]
#[expect(non_snake_case)]
async fn startup_health_check__should_probe_providers_against_test_golden() {
    // Given three mock providers: `healthy` serves the golden hash, `broken` a
    // different one, and `idle` (node 1's) must never be contacted.
    let healthy_server = MockServer::start_async().await;
    let broken_server = MockServer::start_async().await;
    let idle_server = MockServer::start_async().await;
    let healthy_id =
        setup_evm_mock_with_block_hash(&healthy_server, MockAuthExpectation::None, MOCK_BLOCK_HASH);
    let broken_id =
        setup_evm_mock_with_block_hash(&broken_server, MockAuthExpectation::None, &"cc".repeat(32));
    let idle_id =
        setup_evm_mock_with_block_hash(&idle_server, MockAuthExpectation::None, MOCK_BLOCK_HASH);
    let healthy_mock = MockServerExt::new(healthy_server, healthy_id);
    let broken_mock = MockServerExt::new(broken_server, broken_id);
    let idle_mock = MockServerExt::new(idle_server, idle_id);

    let mut node0_providers = NonEmptyBTreeMap::new(
        "healthy".to_string().into(),
        provider(healthy_mock.server.base_url()),
    );
    node0_providers.insert(
        "broken".to_string().into(),
        provider(broken_mock.server.base_url()),
    );
    let node0_chains = ForeignChainsConfig {
        base: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: node0_providers,
        }),
        ..Default::default()
    };
    let node1_chains = ForeignChainsConfig {
        base: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "idle".to_string().into(),
                provider(idle_mock.server.base_url()),
            ),
        }),
        ..Default::default()
    };
    // Golden for node 0 only; node 1 has no entry, so it skips.
    let golden = HealthCheckGoldenConfig {
        base: Some(BlockHashGolden {
            tx: MOCK_TX_ID.to_string(),
            block_hash: MOCK_BLOCK_HASH.to_string(),
        }),
        ..Default::default()
    };

    // When
    let (cluster, _running) =
        common::must_setup_cluster(common::STARTUP_FOREIGN_CHAIN_HEALTH_PORT_SEED, |c| {
            c.foreign_chains.node_configs =
                vec![node0_chains, node1_chains, ForeignChainsConfig::default()];
            c.foreign_chains.node_health_check_goldens = vec![Some(golden)];
        })
        .await;

    // Then — node 0's 1-pass/1-fail verdict, the one log line we match on (its
    // wording is pinned by the node's unit tests).
    let node0 = node_setup(&cluster, 0);
    node0
        .wait_for_log_substring(
            "foreign-chain RPC provider health check complete: 1/2 providers healthy",
            LOG_WAIT_TIMEOUT,
        )
        .await
        .expect("node 0 did not report the expected pass/fail summary");
    // Both probed over HTTP: healthy served the full receipt + finality-head +
    // canonical-block sequence, broken at least one.
    assert!(
        healthy_mock.calls() >= 3,
        "healthy provider got {} calls, expected the full probe sequence",
        healthy_mock.calls()
    );
    assert!(broken_mock.calls() >= 1, "broken provider was never probed");

    // Then — node 1 skipped (no golden), so its provider was never contacted.
    assert_eq!(
        idle_mock.calls(),
        0,
        "node 1 has no golden and must skip, but its provider was probed"
    );

    // Then the Prometheus gauges reflect the probe end to end: `configured` is
    // published for every configured chain up front (so node 1 reports it even
    // though it skips), while `healthy` is emitted only where a probe ran.
    cluster
        .wait_for_metric(
            0,
            metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY,
            |v| v == 1,
            LOG_WAIT_TIMEOUT,
        )
        .await
        .expect("node 0 should report 1 healthy `base` provider");
    assert_eq!(
        cluster
            .get_metric_all_nodes(metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED)
            .await
            .unwrap(),
        vec![Some(2), Some(1), None],
        "configured: node 0 has 2 base providers, node 1 has 1, node 2 none"
    );
    assert_eq!(
        cluster
            .get_metric_all_nodes(metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY)
            .await
            .unwrap(),
        vec![Some(1), None, None],
        "healthy: only node 0 probed (1 of 2 pass); nodes 1 and 2 skipped, so unset"
    );

    // Then the same counts surface on `/debug/node_config`: node 0 overlays its
    // probed `base` count, while the skipped nodes report an empty map (the
    // field is always present, mirroring the provider counts).
    let node0_config = cluster.fetch_node_config(0).await.unwrap();
    assert_eq!(
        node0_config["foreign_chains_provider_health"],
        serde_json::json!({ "base": 1 }),
        "node 0 must expose its healthy `base` count on /debug/node_config"
    );
    for skipped in [1, 2] {
        let config = cluster.fetch_node_config(skipped).await.unwrap();
        assert_eq!(
            config["foreign_chains_provider_health"],
            serde_json::json!({}),
            "node {skipped} skipped its probe, so its health map must be empty"
        );
    }
}
