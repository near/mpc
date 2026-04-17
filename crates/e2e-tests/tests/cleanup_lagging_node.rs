use crate::common;

use std::time::Duration;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::{Curve, DomainPurpose};
use rand::SeedableRng;

const PRESIGNATURES_TO_BUFFER: usize = 8;

/// Verify that when a node falls behind in block ingestion past the
/// `INDEXER_MAX_HEIGHT_DIFF` threshold, the other nodes clean up all
/// presignatures that involved it (offline presignatures go to 0),
/// retain their own presignatures, and can still handle signature requests.
#[tokio::test]
#[expect(non_snake_case)]
async fn cleanup_lagging_node__should_purge_offline_presignatures_and_keep_signing() {
    // given
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let (cluster, running) = common::setup_cluster(common::CLEANUP_LAGGING_NODE_PORT_SEED, |c| {
        c.presignatures_to_buffer = PRESIGNATURES_TO_BUFFER;
    })
    .await;

    assert_eq!(cluster.nodes.len(), 3, "expected 3 nodes");
    assert!(
        !running.domains.domains.is_empty(),
        "expected at least one domain"
    );

    // Wait for all nodes to have presignatures buffered.
    common::wait_for_presignatures(&cluster, &[0, 1, 2], PRESIGNATURES_TO_BUFFER).await;

    // when — disable block ingestion on one node to simulate lagging
    let faulty_node_idx = 0;
    let alive: Vec<usize> = vec![1, 2];
    cluster
        .set_block_ingestion(&[faulty_node_idx], false)
        .expect("failed to disable block ingestion");

    // Wait for the indexer lag to reach the threshold.
    // The alive nodes keep advancing while the faulty node stays behind.
    let lag_timeout = Duration::from_secs(180);
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::INDEXER_LATEST_BLOCK_HEIGHT,
        |_| true, // just need alive nodes to keep advancing
        lag_timeout,
    )
    .await;

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
        |v| v >= PRESIGNATURES_TO_BUFFER as i64,
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
        for _ in 0..2 * PRESIGNATURES_TO_BUFFER {
            let payload = match domain.curve {
                Curve::Secp256k1 | Curve::V2Secp256k1 => common::generate_ecdsa_payload(&mut rng),
                Curve::Edwards25519 => common::generate_eddsa_payload(&mut rng),
                _ => break,
            };
            let outcome = cluster
                .send_sign_request(domain.id, payload)
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
