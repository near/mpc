use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, DEFAULT_PRESIGNATURES_TO_BUFFER, metrics};
use mpc_node_config::MAX_INDEXER_HEIGHT_DIFF;
use near_mpc_contract_interface::types::{Curve, DomainPurpose};
use rand::SeedableRng;

/// Verify that when a node falls behind in block ingestion past the
/// `MAX_INDEXER_HEIGHT_DIFF` threshold, the other nodes clean up all
/// presignatures that involved it (offline presignatures go to 0),
/// retain their own presignatures, and can still handle signature requests.
#[tokio::test]
#[expect(non_snake_case)]
async fn cleanup_lagging_node__should_purge_offline_presignatures_and_keep_signing() {
    // given
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let (cluster, running) =
        common::must_setup_cluster(common::CLEANUP_LAGGING_NODE_PORT_SEED, |_| {}).await;

    // Wait for all nodes to have presignatures buffered.
    common::wait_for_presignatures(&cluster, &[0, 1, 2], DEFAULT_PRESIGNATURES_TO_BUFFER)
        .await
        .expect("presignatures did not buffer");

    // when — disable block ingestion on one node to simulate lagging
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

    // Wait for offline presignatures to be cleaned up on alive nodes.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_OFFLINE,
        |v| v == 0,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("offline presignatures not cleaned up");

    // then — online presignatures should remain at buffer amount on alive nodes
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v >= DEFAULT_PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("online presignatures below buffer amount");

    // Verify nodes can still handle signature requests by depleting their asset stores.
    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
        .expect("cluster must have at least one signable domain");
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
