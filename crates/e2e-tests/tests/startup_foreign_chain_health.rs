use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use crate::common;

use e2e_tests::foreign_chain_mock::{
    EVM_IDENTITY_PROBE_CALLS, MockAuthExpectation, MockServerExt, setup_evm_identity_mock,
};
use httpmock::MockServer;
use mpc_node_config::{
    ExpectedIdentities, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;

const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// `base` mainnet chain id: decimal in the config identity, hex over `eth_chainId`.
const BASE_CHAIN_ID: &str = "8453";
const BASE_CHAIN_ID_HEX: &str = "0x2105";
/// A different network's chain id, to make a provider fail the identity check.
const WRONG_CHAIN_ID_HEX: &str = "0x1";

fn provider(rpc_url: String) -> ForeignChainProviderConfig {
    ForeignChainProviderConfig {
        rpc_url,
        auth: Default::default(),
    }
}

fn base_chains(
    providers: NonEmptyBTreeMap<
        mpc_node_config::foreign_chains::RpcProviderName,
        ForeignChainProviderConfig,
    >,
) -> ForeignChainsConfig {
    ForeignChainsConfig {
        base: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers,
        }),
        ..Default::default()
    }
}

/// Poll a mock's hit count until it reaches `target`, or fail after `timeout`. Used to
/// synchronize on the detached startup probe without matching log lines.
async fn wait_for_calls(mock: &MockServerExt, target: usize, timeout: Duration) {
    let start = Instant::now();
    loop {
        if mock.calls() >= target {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "timed out waiting for {target} calls; the provider got {}",
                mock.calls()
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The startup foreign-chain health check runs on the real mpc-node startup path, probing each
/// node's configured providers by chain identity plus a recent transaction.
///
/// Node 0 (`base` + the matching identity, two providers) passes one and fails the other;
/// node 1 (`base` configured but no identity) fails before contacting its provider; node 2
/// (nothing configured) probes nothing.
#[tokio::test]
#[expect(non_snake_case)]
async fn startup_health_check__should_probe_providers_by_chain_identity() {
    // Given three mock providers: `healthy` reports the expected chain id and serves a
    // verifiable recent transaction, `broken` reports a different network's chain id, and
    // `idle` (node 1's) must never be contacted.
    let healthy_server = MockServer::start_async().await;
    let broken_server = MockServer::start_async().await;
    let idle_server = MockServer::start_async().await;
    let healthy_id = setup_evm_identity_mock(
        &healthy_server,
        MockAuthExpectation::None,
        BASE_CHAIN_ID_HEX,
    );
    let broken_id = setup_evm_identity_mock(
        &broken_server,
        MockAuthExpectation::None,
        WRONG_CHAIN_ID_HEX,
    );
    let idle_id =
        setup_evm_identity_mock(&idle_server, MockAuthExpectation::None, BASE_CHAIN_ID_HEX);
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
    let node0_chains = base_chains(node0_providers);
    let node1_chains = base_chains(NonEmptyBTreeMap::new(
        "idle".to_string().into(),
        provider(idle_mock.server.base_url()),
    ));

    // Node 0 has the `base` identity; node 1 has none, so its `base` check fails without probing.
    let node0_identities = ExpectedIdentities {
        base: Some(BASE_CHAIN_ID.to_string()),
        ..Default::default()
    };

    // When
    let (cluster, _running) =
        common::must_setup_cluster(common::STARTUP_FOREIGN_CHAIN_HEALTH_PORT_SEED, |c| {
            c.foreign_chains.node_configs =
                vec![node0_chains, node1_chains, ForeignChainsConfig::default()];
            c.foreign_chains.node_health_check_identities = vec![node0_identities];
        })
        .await;

    // Then — node 0's healthy provider ran the full identity probe over HTTP.
    wait_for_calls(&healthy_mock, EVM_IDENTITY_PROBE_CALLS, PROBE_TIMEOUT).await;
    // The wrong-network provider is rejected right after the chain-id call.
    assert_eq!(
        broken_mock.calls(),
        1,
        "broken provider reported the wrong chain id and must be rejected after eth_chainId"
    );
    // Node 1 configured `base` but no identity, so its check fails before touching the provider.
    assert_eq!(
        idle_mock.calls(),
        0,
        "node 1 has no configured identity and must fail before probing its provider"
    );

    drop(cluster);
}
