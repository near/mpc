use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::DomainPurpose;
use rand::{SeedableRng, rngs::StdRng};

const TRIPLES_TO_BUFFER: usize = 8;
const SIGN_REQUESTS: usize = 8;

/// Verify that when a node is killed and its DB wiped, the remaining nodes
/// detect it as offline, purge all triples that involved it, and can
/// still process signature requests. The dead node can be restarted and
/// rejoin successfully.
#[tokio::test]
async fn dead_node_triples_purged_and_signing_recovers() {
    // Given
    let mut rng = StdRng::seed_from_u64(0);
    let (mut cluster, running) = common::must_setup_cluster(common::LOST_ASSETS_PORT_SEED, |c| {
        c.triples_to_buffer = TRIPLES_TO_BUFFER;
    })
    .await;

    assert_eq!(cluster.nodes.len(), 3, "expected 3 nodes");
    assert!(
        !running.domains.domains.is_empty(),
        "expected at least one domain"
    );

    let dead_idx = 0;
    let alive: Vec<usize> = (1..3).collect();

    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_TRIPLES_ONLINE,
        |v| v >= TRIPLES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("triples did not buffer");

    // When
    // Kill the node and wipe its data: its share of every triple is gone.
    cluster
        .kill_nodes(&[dead_idx])
        .expect("failed to kill node");
    cluster.wipe_db(&[dead_idx]).expect("failed to wipe DB");

    // A triple generation batch has a single random partner, so whether a surviving node held
    // triples with the dead node at all is up to chance: only the end state is deterministic.
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_TRIPLES_OFFLINE,
        |v| v == 0,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("triples with the dead node were not purged");
    common::wait_metric_on_nodes(
        &cluster,
        &alive,
        metrics::OWNED_TRIPLES_ONLINE,
        |v| v >= TRIPLES_TO_BUFFER as i64,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("triples did not rebuild on surviving nodes");

    // Then
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
    {
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

    // Restart the dead node with a clean state and wait for it to be healthy.
    cluster
        .reset_and_start_nodes(&[dead_idx])
        .await
        .expect("failed to restart dead node");

    // Node 0 restarted with a wiped DB: it has no keyshare and cannot generate triples
    // until a resharing redistributes keys to it, so we only wait on the surviving nodes.
    common::wait_for_triples(&cluster, &alive, TRIPLES_TO_BUFFER)
        .await
        .expect("triples did not rebuild after restart");

    // Sanity-check: one final sign request after the node has rejoined.
    if let Some(domain) = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
    {
        let payload = common::must_get_payload_for_domain(domain, &mut rng);
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
