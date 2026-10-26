use crate::common;

use e2e_tests::metrics;
use rand::{SeedableRng, rngs::StdRng};

/// Sign requests must keep succeeding when a node is online but cannot land
/// its `respond` transactions: a failover leader takes over after the failover
/// interval. This test stands up a 2-of-2 cluster and deletes node 0's NEAR
/// signer key, leaving it a fully participating node whose transactions the
/// chain rejects. The leader is pseudorandom per request, so requests are sent
/// until one picks node 0 as its leader and node 1's failover answers it.
#[tokio::test]
#[expect(non_snake_case)]
async fn leader_failover__should_answer_requests_whose_leader_cannot_submit_responses() {
    const MAX_SIGN_REQUESTS: usize = 15;

    // Given
    let mut rng = StdRng::seed_from_u64(0);
    let (cluster, running) = common::must_setup_cluster(common::LEADER_FAILOVER_PORT_SEED, |c| {
        c.num_nodes = 2;
        c.threshold = 2;
    })
    .await;
    cluster
        .delete_node_signer_key(0)
        .await
        .expect("failed to delete node 0's signer key");

    // When
    let mut requests_sent = 0;
    let mut failover_attempts = 0;
    while failover_attempts == 0 && requests_sent < MAX_SIGN_REQUESTS {
        common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
            .await
            .expect("sign request failed while node 0 cannot submit responses");
        requests_sent += 1;
        // The counter has no series until the first failover attempt, so a
        // missing metric reads as zero.
        failover_attempts = cluster
            .get_metric_all_nodes(metrics::FAILOVER_LEADER_ATTEMPTS)
            .await
            .expect("failed to scrape metrics")[1]
            .unwrap_or(0);
    }

    // Then
    assert!(
        failover_attempts >= 1,
        "no request was answered by a failover leader within {requests_sent} sign requests"
    );
}
