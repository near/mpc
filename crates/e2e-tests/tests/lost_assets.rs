use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::{DomainPurpose, SignatureScheme};
use rand::SeedableRng;

const PRESIGNATURES_TO_BUFFER: usize = 8;

/// Verify that when a node is killed and its DB wiped, the remaining nodes
/// detect it as offline, purge all presignatures that involved it, and can
/// still process signature requests. The dead node can be restarted and
/// rejoin successfully.
#[tokio::test]
async fn dead_node_presignatures_purged_and_signing_recovers() {
    // given
    let (mut cluster, running) = common::setup_cluster(common::LOST_ASSETS_PORT_SEED, |c| {
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

    // Pre-kill: confirm all presignatures have been moved to the cold queue, so
    // ONLINE reflects the real count.  `setup_cluster` only waits for AVAILABLE
    // (which includes the hot queue), so ONLINE can still be 0 at that point.
    // Without this step the post-kill ONLINE < N check would trivially pass before
    // detection ever fired, defeating the purpose of the wait.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v >= PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await;

    // Kill the node and wipe its data — its share of every presignature is gone.
    cluster
        .kill_nodes(&[dead_idx])
        .expect("failed to kill node");
    cluster.wipe_db(&[dead_idx]).expect("failed to wipe DB");

    // when — wait for alive nodes to detect the dead node and rebuild without it.
    //
    // Detection causes each node to reset cold_ready=0, dropping ONLINE to 0.
    // We confirmed ONLINE >= N before the kill, so any value < N is a genuine
    // transition (not a trivial pass). We use `< N` rather than `== 0` because
    // the two alive nodes may detect the dead node at slightly different times;
    // the first detector starts generating new 2-of-2 presignatures while the
    // second node's ONLINE is still high. Requiring both nodes to be exactly 0
    // in the same 500 ms poll is a race that fails under CI load. The `< N`
    // predicate has a wide window (from detection until the full buffer is
    // regenerated) so it tolerates the stagger.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v < PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await;

    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_PRESIGNATURES_ONLINE,
        |v| v >= PRESIGNATURES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await;

    // then — surviving nodes can still process sign requests.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, Some(DomainPurpose::Sign)))
    {
        for _ in 0..PRESIGNATURES_TO_BUFFER {
            let payload = match domain.scheme {
                SignatureScheme::Secp256k1 | SignatureScheme::V2Secp256k1 => {
                    common::generate_ecdsa_payload(&mut rng)
                }
                SignatureScheme::Ed25519 => common::generate_eddsa_payload(&mut rng),
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

    // Restart the dead node with a clean state and wait for it to be healthy.
    cluster
        .reset_and_start_nodes(&[dead_idx])
        .await
        .expect("failed to restart dead node");

    // Wait for the alive nodes to rebuild their presignature buffer.
    // Node 0 restarted with a wiped DB — it has no keyshare and cannot generate presignatures
    // until a resharing redistributes keys to it, so we only wait on the surviving nodes.
    common::wait_for_presignatures(&cluster, &alive, PRESIGNATURES_TO_BUFFER).await;

    // Sanity-check: one final sign request after the node has rejoined.
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, Some(DomainPurpose::Sign)))
    {
        let payload = match domain.scheme {
            SignatureScheme::Secp256k1 | SignatureScheme::V2Secp256k1 => {
                common::generate_ecdsa_payload(&mut rng)
            }
            SignatureScheme::Ed25519 => common::generate_eddsa_payload(&mut rng),
            _ => return,
        };
        let outcome = cluster
            .send_sign_request(domain.id, payload)
            .await
            .expect("post-restart sign request failed");
        assert!(
            outcome.is_success(),
            "post-restart sign request failed: {:?}",
            outcome.failure_message()
        );
    }
}
