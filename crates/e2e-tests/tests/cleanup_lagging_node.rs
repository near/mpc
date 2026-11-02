use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, DEFAULT_TRIPLES_TO_BUFFER, metrics};
use mpc_node_config::MAX_INDEXER_HEIGHT_DIFF;
use near_mpc_contract_interface::types::DomainPurpose;
use rand::{SeedableRng, rngs::StdRng};

const SIGN_REQUESTS: usize = 20;

/// Verify that when a node falls behind in block ingestion past the
/// `MAX_INDEXER_HEIGHT_DIFF` threshold, the other nodes clean up all
/// triples that involved it (offline triples go to 0),
/// retain their own triples, and can still handle signature requests.
#[tokio::test]
#[expect(non_snake_case)]
async fn cleanup_lagging_node__should_purge_offline_triples_and_keep_signing() {
    // Given
    let mut rng = StdRng::seed_from_u64(0);
    let (cluster, running) =
        common::must_setup_cluster(common::CLEANUP_LAGGING_NODE_PORT_SEED, |_| {}).await;

    common::wait_for_triples(&cluster, &[0, 1, 2], DEFAULT_TRIPLES_TO_BUFFER)
        .await
        .expect("triples did not buffer");

    // When
    let faulty_node_idx = 0;
    let alive: Vec<usize> = vec![1, 2];
    cluster
        .set_block_ingestion(&[faulty_node_idx], false)
        .expect("failed to disable block ingestion");

    // Wait until alive nodes are at least MAX_INDEXER_HEIGHT_DIFF blocks ahead
    // of the faulty node. The faulty node may still process a few buffered blocks
    // after ingestion is disabled, so we compare heights dynamically each poll.
    common::wait_for_indexer_lag(
        &cluster,
        faulty_node_idx,
        &alive,
        MAX_INDEXER_HEIGHT_DIFF as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("alive nodes did not advance past faulty node");

    // Then
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_TRIPLES_OFFLINE,
        |v| v == 0,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("offline triples not cleaned up");

    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_TRIPLES_ONLINE,
        |v| v >= DEFAULT_TRIPLES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("online triples below buffer amount");

    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
        .expect("cluster must have at least one signable domain");
    for _ in 0..SIGN_REQUESTS {
        let payload = common::must_get_payload_for_domain(domain, &mut rng);
        let outcome = cluster
            .send_sign_request(domain.id, payload, cluster.default_user_account())
            .await
            .expect("sign request failed");
        assert!(
            outcome.is_success(),
            "sign request failed: {:?}",
            outcome.failure_message()
        );
    }
}
