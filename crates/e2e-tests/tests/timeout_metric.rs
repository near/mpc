use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, WithTimeout, metrics};
use near_mpc_contract_interface::types::{DomainPurpose, SignRequestArgs};
use rand::{SeedableRng, rngs::StdRng};

/// When a sign request can't be answered (because too many participants are
/// down), the contract calls `fail_on_timeout` and each alive node's indexer
/// bumps `mpc_num_timeouts_indexed`. This test stands up a 2-of-2 cluster,
/// kills one node, submits a sign request, and verifies the surviving node
/// observes the timeout.
#[tokio::test]
#[expect(non_snake_case)]
async fn timeout_metric__should_increment_when_signature_times_out() {
    // given — 2-of-2 cluster (one node down ⇒ signing impossible)
    let mut rng = StdRng::seed_from_u64(0);
    let (mut cluster, running) =
        common::must_setup_cluster(common::TIMEOUT_METRIC_PORT_SEED, |c| {
            c.num_nodes = 2;
            c.threshold = 2;
        })
        .await;
    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| matches!(d.purpose, DomainPurpose::Sign))
        .expect("cluster must have a signable domain");

    // when — kill node 0, then submit a request no one can answer
    cluster.kill_nodes(&[0]).expect("failed to kill node 0");

    let payload = common::must_get_payload_for_domain(domain, &mut rng);

    // then — the request is unanswerable, so the contract's yield auto-timeout is its
    // outcome. That resolves long after the RPC's wait window, so the deadline has to
    // cover it.
    let outcome = cluster
        .contract_handle(cluster.default_user_account())
        .with_timeout(CLUSTER_WAIT_TIMEOUT)
        .sign(SignRequestArgs {
            path: "test".to_string(),
            payload,
            domain_id: domain.id,
        })
        .await
        .expect("sign request did not reach an on-chain outcome");
    assert!(
        outcome.is_failure(),
        "sign request succeeded with only 1 of its 2 required signers alive"
    );

    common::wait_metric_on_nodes(
        &cluster,
        &[1],
        metrics::TIMEOUTS_INDEXED,
        // Inclusion may be re-sent by near-kit's transport retries, so a duplicate
        // request can bump this twice. C.f.
        // https://github.com/near/mpc/pull/3211#discussion_r3233189801
        |v| v >= 1,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .unwrap_or_else(|_| panic!("{} did not reach 1 on node 1", metrics::TIMEOUTS_INDEXED));
}
