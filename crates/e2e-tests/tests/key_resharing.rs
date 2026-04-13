use crate::common;

use near_mpc_contract_interface::types::AttemptId;
use rand::SeedableRng;

/// Port of pytest `test_key_event::test_single_domain`.
///
/// Tests single-domain key generation and multiple rounds of resharing
/// with participant set changes, verifying liveness after each round.
#[tokio::test]
async fn test_key_resharing() {
    // Start 5 nodes but only 2 as initial participants. Node 4 stays idle
    // (syncing) so it can be used as a fresh replacement when node 0 is dropped.
    let (cluster, running) = common::setup_cluster(common::KEY_RESHARING_PORT_SEED, |c| {
        c.num_nodes = 5;
        c.initial_participant_indices = (0..2).collect();
        c.triples_to_buffer = 2;
        c.presignatures_to_buffer = 2;
    })
    .await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    // Verify initial state: 2 participants, threshold 2.
    assert_eq!(running.parameters.participants.participants.len(), 2);

    // Send sign + CKD requests to verify liveness.
    common::send_sign_request(&cluster, &running, &mut rng).await;
    common::send_ckd_request(&cluster, &running, &mut rng).await;

    // Resharing 1: expand from 2 → 4 nodes, threshold 3.
    tracing::info!("resharing 1: expanding to 4 nodes, threshold 3");
    cluster
        .start_resharing_and_wait(&[0, 1, 2, 3], 3)
        .await
        .expect("resharing 1 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 4);
    common::send_sign_request(&cluster, &running, &mut rng).await;
    common::send_ckd_request(&cluster, &running, &mut rng).await;

    // Resharing 2: shrink to nodes [1,2,3] (drop node 0), threshold 3.
    tracing::info!("resharing 2: dropping node 0");
    cluster
        .start_resharing_and_wait(&[1, 2, 3], 3)
        .await
        .expect("resharing 2 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 3);
    common::send_sign_request(&cluster, &running, &mut rng).await;

    // Resharing 3: add node 4 (has been running and syncing since startup)
    // to replace the dropped node 0. Back to 4 participants, threshold 3.
    tracing::info!("resharing 3: adding node 4 to replace dropped node 0");
    cluster
        .start_resharing_and_wait(&[1, 2, 3, 4], 3)
        .await
        .expect("resharing 3 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 4);
    common::send_ckd_request(&cluster, &running, &mut rng).await;
    common::send_sign_request(&cluster, &running, &mut rng).await;

    // Resharing 4: increase threshold to 4 (all participants required).
    tracing::info!("resharing 4: increasing threshold to 4");
    cluster
        .start_resharing_and_wait(&[1, 2, 3, 4], 4)
        .await
        .expect("resharing 4 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 4);

    // Verify attempt IDs are stable across resharing rounds.
    for key in &running.keyset.domains {
        assert_eq!(
            key.attempt,
            AttemptId(0),
            "domain {:?} should have attempt 0 after resharing",
            key.domain_id
        );
    }
    common::send_sign_request(&cluster, &running, &mut rng).await;
    common::send_ckd_request(&cluster, &running, &mut rng).await;
}

async fn expect_running_state(
    cluster: &e2e_tests::MpcCluster,
) -> near_mpc_contract_interface::types::RunningContractState {
    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get state");
    match state {
        near_mpc_contract_interface::types::ProtocolContractState::Running(r) => r,
        other => panic!("expected Running, got: {other:?}"),
    }
}
