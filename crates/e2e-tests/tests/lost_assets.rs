use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use mpc_primitives::domain::Curve;
use near_mpc_contract_interface::types::DomainPurpose;
use rand::SeedableRng;

const PRESIGNATURES_TO_BUFFER: usize = 8;

/// Verify that when a node is killed and its DB wiped, the remaining nodes
/// detect it as offline, purge all presignatures that involved it, and can
/// still process signature requests. The dead node can be restarted and
/// rejoin successfully.
#[tokio::test]
async fn dead_node_presignatures_purged_and_signing_recovers() {
    // given
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let (mut cluster, running) = common::must_setup_cluster(common::LOST_ASSETS_PORT_SEED, |c| {
        c.presignatures_to_buffer = PRESIGNATURES_TO_BUFFER;
    })
    .await;

    assert_eq!(cluster.nodes.len(), 3, "expected 3 nodes");
    assert!(
        !running.domains.domains.is_empty(),
        "expected at least one domain"
    );

    let dead_idx = 0;
    let alive: Vec<usize> = (1..3).collect();

    // Wait for buffered presignatures to reach PRESIGNATURES_TO_BUFFER.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v >= PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("presignatures did not buffer");

    // when
    // Kill the node and wipe its data — its share of every presignature is gone.
    cluster
        .kill_nodes(&[dead_idx])
        .expect("failed to kill node");
    cluster.wipe_db(&[dead_idx]).expect("failed to wipe DB");

    // Wait for buffered presignatures to decrease as a result of killed node.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v < PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("presignatures did not decrease after killing node");

    // Wait for buffered presignatures to reach again PRESIGNATURES_TO_BUFFER
    // among nodes that are still alive.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v >= PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("presignatures did not rebuild on surviving nodes");

    // then — surviving nodes can still process sign requests.
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
    {
        for _ in 0..PRESIGNATURES_TO_BUFFER {
            let payload = match domain.curve {
                Curve::Secp256k1 => common::generate_ecdsa_payload(&mut rng),
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

    // Restart the dead node with a clean state and wait for it to be healthy.
    cluster
        .reset_and_start_nodes(&[dead_idx])
        .await
        .expect("failed to restart dead node");

    // Wait for the alive nodes to rebuild their presignature buffer.
    // Node 0 restarted with a wiped DB — it has no keyshare and cannot generate presignatures
    // until a resharing redistributes keys to it, so we only wait on the surviving nodes.
    common::wait_for_presignatures(&cluster, &alive, PRESIGNATURES_TO_BUFFER)
        .await
        .expect("presignatures did not rebuild after restart");

    // Sanity-check: one final sign request after the node has rejoined.
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
    {
        let payload = match domain.curve {
            Curve::Secp256k1 => common::generate_ecdsa_payload(&mut rng),
            Curve::Edwards25519 => common::generate_eddsa_payload(&mut rng),
            _ => return,
        };
        let outcome = cluster
            .send_sign_request(domain.id, payload, cluster.default_user_account())
            .await
            .expect("post-restart sign request failed");
        assert!(
            outcome.is_success(),
            "post-restart sign request failed: {:?}",
            outcome.failure_message()
        );
    }
}
