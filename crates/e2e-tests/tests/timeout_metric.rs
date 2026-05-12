use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::{Curve, DomainPurpose};
use rand::SeedableRng;

/// When a sign request can't be answered (because too many participants are
/// down), the contract calls `fail_on_timeout` and each alive node's indexer
/// bumps `mpc_num_timeouts_indexed`. This test stands up a 2-of-2 cluster,
/// kills one node, submits a sign request, and verifies the surviving node
/// observes the timeout.
#[tokio::test]
#[expect(non_snake_case)]
async fn timeout_metric__should_increment_when_signature_times_out() {
    // given — 2-of-2 cluster (one node down ⇒ signing impossible)
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
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

    let payload = match domain.curve {
        Curve::Secp256k1 => common::generate_ecdsa_payload(&mut rng),
        Curve::Edwards25519 => common::generate_eddsa_payload(&mut rng),
        c => panic!("unsupported curve in test: {c:?}"),
    };

    let outcome = cluster
        .send_sign_request(domain.id, payload, cluster.default_user_account())
        .await
        .expect("expected success");

    // sanity check
    assert!(
        outcome.is_success(),
        "sign request for domain {:?} failed: {:?}",
        domain.id,
        outcome.failure_message()
    );

    // when — kill node 0, then submit a request no one can answer
    cluster.kill_nodes(&[0]).expect("failed to kill node 0");

    let payload = match domain.curve {
        Curve::Secp256k1 => common::generate_ecdsa_payload(&mut rng),
        Curve::Edwards25519 => common::generate_eddsa_payload(&mut rng),
        c => panic!("unsupported curve in test: {c:?}"),
    };

    let outcome = cluster
        .send_sign_request(domain.id, payload, cluster.default_user_account())
        .await
        .expect("expected success");

    // sanity check
    assert!(outcome.is_failure(), "expected sign request to fail",);

    // Then: expect metric to kick in
    common::wait_metric_on_nodes(
        &cluster,
        &[1],
        metrics::TIMEOUTS_INDEXED,
        |v| v == 1,
        CLUSTER_WAIT_TIMEOUT,
    )
    .await
    .expect("mpc_num_timeouts_indexed did not reach 1 on node 1");
}
