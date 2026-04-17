use crate::common;

use backon::Retryable;
use e2e_tests::{CLUSTER_WAIT_TIMEOUT, DEFAULT_PRESIGNATURES_TO_BUFFER, metrics};
use near_mpc_contract_interface::types::{Curve, DomainPurpose};
use rand::SeedableRng;

/// Maximum block delay before an MPC node is considered offline by its peers.
/// Must match `MAX_HEIGHT_DIFF` in `crates/node/src/network.rs`.
const INDEXER_MAX_HEIGHT_DIFF: i64 = 50;

/// Verify that when a node falls behind in block ingestion past the
/// `INDEXER_MAX_HEIGHT_DIFF` threshold, the other nodes clean up all
/// presignatures that involved it (offline presignatures go to 0),
/// retain their own presignatures, and can still handle signature requests.
#[tokio::test]
async fn cleanup_lagging_node_should_purge_offline_presignatures_and_keep_signing() {
    // given
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let (cluster, running) =
        common::setup_cluster(common::CLEANUP_LAGGING_NODE_PORT_SEED, |_| {}).await;

    assert_eq!(cluster.nodes.len(), 3, "expected 3 nodes");
    assert!(
        !running.domains.domains.is_empty(),
        "expected at least one domain"
    );

    // Wait for all nodes to have presignatures buffered.
    common::wait_for_presignatures(&cluster, &[0, 1, 2], DEFAULT_PRESIGNATURES_TO_BUFFER).await;

    // when — disable block ingestion on one node to simulate lagging
    let faulty_node_idx = 0;
    let alive: Vec<usize> = vec![1, 2];
    cluster
        .set_block_ingestion(&[faulty_node_idx], false)
        .expect("failed to disable block ingestion");

    // Wait until alive nodes are at least INDEXER_MAX_HEIGHT_DIFF blocks ahead
    // of the faulty node. The faulty node may still process a few buffered blocks
    // after ingestion is disabled, so we compare heights dynamically each poll.
    (|| async {
        let heights = cluster
            .get_metric_all_nodes(metrics::INDEXER_LATEST_BLOCK_HEIGHT)
            .await
            .expect("failed to get metrics");
        let faulty = heights[faulty_node_idx].unwrap_or(0);
        for &idx in &alive {
            anyhow::ensure!(
                heights[idx].unwrap_or(0) >= faulty + INDEXER_MAX_HEIGHT_DIFF,
                "node {idx} not yet {} blocks ahead of faulty node (alive={:?}, faulty={faulty})",
                INDEXER_MAX_HEIGHT_DIFF,
                heights[idx],
            );
        }
        Ok(())
    })
    .retry(
        backon::ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("alive nodes did not pull ahead of faulty node");

    // Wait for offline presignatures to be cleaned up on alive nodes.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_OFFLINE,
        |v| v == 0,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await;

    // then — online presignatures should remain at buffer amount on alive nodes
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v >= DEFAULT_PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await;

    // Verify nodes can still handle signature requests by depleting their asset stores.
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
    {
        for _ in 0..2 * DEFAULT_PRESIGNATURES_TO_BUFFER {
            let payload = match domain.curve {
                Curve::Secp256k1 | Curve::V2Secp256k1 => common::generate_ecdsa_payload(&mut rng),
                Curve::Edwards25519 => common::generate_eddsa_payload(&mut rng),
                _ => break,
            };
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

    // Re-enable block ingestion.
    cluster
        .set_block_ingestion(&[faulty_node_idx], true)
        .expect("failed to re-enable block ingestion");
}
