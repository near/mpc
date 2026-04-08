mod common;

use near_mpc_contract_interface::types::{DomainPurpose, ProtocolContractState, SignatureScheme};

/// Tests resharing cancellation and retry.
///
/// Setup: 6 nodes, 3 initial participants (threshold 2). Begin resharing to
/// nodes [0..5] with threshold 3, kill node 4 so resharing stalls, cancel it,
/// then retry resharing using node 5 (which has been running and syncing the
/// whole time) instead of the killed node 4.
#[tokio::test]
async fn test_cancellation_of_resharing() {
    let (mut cluster, _running) =
        common::setup_cluster(common::CANCELLATION_OF_RESHARING_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participants = 3;
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
        })
        .await;

    // Begin resharing to 5 nodes [0..5], threshold 3.
    tracing::info!("beginning resharing to nodes 0-4, threshold 3");
    cluster
        .start_resharing(&[0, 1, 2, 3, 4], 3)
        .await
        .expect("start_resharing failed");

    // Kill node 4 so resharing can't complete.
    tracing::info!("killing node 4 to block resharing");
    cluster.kill_nodes(&[4]).expect("failed to kill node 4");

    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get state");
    assert!(
        matches!(&state, ProtocolContractState::Resharing(_)),
        "expected Resharing state, got: {state:?}"
    );

    // Vote cancel from a non-previous-participant — contract should reject.
    tracing::info!("voting cancel from non-participant node 3 (expect rejection)");
    let outcome = cluster
        .vote_cancel_resharing_from(3)
        .await
        .expect("failed to send cancel vote");
    assert!(
        !outcome.is_success(),
        "cancel vote from non-participant should fail"
    );
    let failure = outcome.failure_message().unwrap_or_default();
    assert!(
        failure.contains("Not a participant"),
        "unexpected failure: {failure}"
    );

    // Vote cancel from threshold (2) previous participants.
    tracing::info!("voting cancel from participants 0 and 1");
    for node_idx in [0, 1] {
        let outcome = cluster
            .vote_cancel_resharing_from(node_idx)
            .await
            .expect("failed to send cancel vote");
        assert!(
            outcome.is_success(),
            "cancel vote from node {node_idx} failed: {:?}",
            outcome.failure_message()
        );
    }

    // Wait for Running state after cancellation.
    cluster
        .wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("contract did not return to Running after cancellation");

    // Verify previously_cancelled_resharing_epoch_id is set.
    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get state");
    let running = match &state {
        ProtocolContractState::Running(r) => r,
        other => panic!("expected Running, got: {other:?}"),
    };
    assert_eq!(
        running.previously_cancelled_resharing_epoch_id,
        Some(near_mpc_contract_interface::types::EpochId(1)),
        "previously_cancelled_resharing_epoch_id should be 1 (the prospective epoch)"
    );
    tracing::info!("resharing cancelled successfully");

    // Verify liveness after cancellation.
    for _ in 0..3 {
        send_sign_request(&cluster, running).await;
        send_ckd_request(&cluster, running).await;
    }

    // Retry resharing using node 5 (running since startup, fully synced)
    // instead of the killed node 4.
    tracing::info!("retrying resharing with node 5 instead of killed node 4");
    cluster
        .start_resharing_and_wait(&[0, 1, 2, 3, 5], 3)
        .await
        .expect("retry resharing failed");

    // Verify previously_cancelled_resharing_epoch_id is cleared.
    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get state");
    let running = match &state {
        ProtocolContractState::Running(r) => r,
        other => panic!("expected Running, got: {other:?}"),
    };
    assert!(
        running.previously_cancelled_resharing_epoch_id.is_none(),
        "previously_cancelled_resharing_epoch_id should be cleared after successful resharing"
    );

    // Final liveness check.
    for _ in 0..3 {
        send_sign_request(&cluster, running).await;
        send_ckd_request(&cluster, running).await;
    }
}

async fn send_sign_request(
    cluster: &e2e_tests::MpcCluster,
    running: &near_mpc_contract_interface::types::RunningContractState,
) {
    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.scheme == SignatureScheme::Secp256k1 && d.purpose == Some(DomainPurpose::Sign))
        .expect("no Secp256k1 Sign domain");
    let outcome = cluster
        .send_sign_request(domain.id, common::generate_ecdsa_payload())
        .await
        .expect("sign request failed");
    assert!(
        outcome.is_success(),
        "sign request failed: {:?}",
        outcome.failure_message()
    );
}

async fn send_ckd_request(
    cluster: &e2e_tests::MpcCluster,
    running: &near_mpc_contract_interface::types::RunningContractState,
) {
    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.purpose == Some(DomainPurpose::CKD))
        .expect("no CKD domain");
    let outcome = cluster
        .send_ckd_request(domain.id, common::generate_ckd_app_public_key())
        .await
        .expect("ckd request failed");
    assert!(
        outcome.is_success(),
        "ckd request failed: {:?}",
        outcome.failure_message()
    );
}
