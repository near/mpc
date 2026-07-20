use std::num::NonZeroU64;
use std::time::Duration;

use crate::common;

use e2e_tests::MpcNodeState;
use e2e_tests::foreign_chain_mock::{
    MOCK_BLOCK_HASH, MOCK_TX_ID, MockAuthExpectation, MockServerExt, setup_evm_mock_with_block_hash,
};
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

/// The startup foreign-chain RPC provider health check runs on the real
/// startup path of the spawned mpc-node binary, probing the providers a node
/// has configured against golden values supplied by this test case.
///
/// Node 0 carries a `base` config with two providers — one serving the golden
/// block hash, one serving a different one — plus the matching golden values;
/// its probe must genuinely pass one provider and fail the other. Node 1 has
/// no golden values, so on this local chain it must skip without probing.
#[tokio::test]
#[expect(non_snake_case)]
async fn startup_health_check__should_probe_providers_against_test_golden() {
    // Given — two mock base providers: `healthy` answers with the golden
    // block hash, `broken` with a different one.
    let healthy_server = MockServer::start_async().await;
    let broken_server = MockServer::start_async().await;
    let healthy_id =
        setup_evm_mock_with_block_hash(&healthy_server, MockAuthExpectation::None, MOCK_BLOCK_HASH);
    let broken_id =
        setup_evm_mock_with_block_hash(&broken_server, MockAuthExpectation::None, &"cc".repeat(32));
    let healthy_mock = MockServerExt::new(healthy_server, healthy_id);
    let broken_mock = MockServerExt::new(broken_server, broken_id);

    let mut providers = NonEmptyBTreeMap::new(
        "healthy".to_string().into(),
        provider(healthy_mock.server.base_url()),
    );
    providers.insert(
        "broken".to_string().into(),
        provider(broken_mock.server.base_url()),
    );
    let foreign_chains = ForeignChainsConfig {
        base: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers,
        }),
        ..Default::default()
    };
    // The golden targets and the expected result are both owned by the test.
    let golden = HealthCheckGoldenConfig {
        base: Some(BlockHashGolden {
            tx: MOCK_TX_ID.to_string(),
            block_hash: MOCK_BLOCK_HASH.to_string(),
        }),
        ..Default::default()
    };

    // When — the cluster starts: node 0 with providers + golden, the rest bare.
    let (cluster, _running) =
        common::must_setup_cluster(common::STARTUP_FOREIGN_CHAIN_HEALTH_PORT_SEED, |c| {
            c.foreign_chains.node_configs = vec![
                foreign_chains,
                ForeignChainsConfig::default(),
                ForeignChainsConfig::default(),
            ];
            c.foreign_chains.node_health_check_goldens = vec![Some(golden)];
        })
        .await;

    // Then — node 0 probed on startup and got one pass, one fail.
    let node0 = node_setup(&cluster, 0);
    node0
        .wait_for_log_substring(
            "running foreign-chain RPC provider health check with config-supplied golden values",
            LOG_WAIT_TIMEOUT,
        )
        .await
        .expect("node 0 did not run the startup health check");
    node0
        .wait_for_log_substring(
            "foreign-chain RPC provider health check complete: 1/2 providers healthy",
            LOG_WAIT_TIMEOUT,
        )
        .await
        .expect("node 0 did not report the expected pass/fail summary");
    // Receipt + finality head + canonical block lookups.
    assert!(
        healthy_mock.calls() >= 3,
        "healthy provider got {} calls, expected the full probe sequence",
        healthy_mock.calls()
    );
    assert!(broken_mock.calls() >= 1, "broken provider was never probed");

    // Then — node 1 has no golden values: it skipped without probing.
    let node1 = node_setup(&cluster, 1);
    node1
        .wait_for_log_substring(
            "local or custom chain; skipping foreign-chain RPC provider health check",
            LOG_WAIT_TIMEOUT,
        )
        .await
        .expect("node 1 did not log the local-chain skip");
    assert!(
        !node1
            .stdout_log()
            .expect("node 1 stdout log unreadable")
            .contains("running foreign-chain RPC provider health check"),
        "node 1 must not probe without golden values"
    );
}
