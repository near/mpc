mod common;

use near_mpc_contract_interface::types::{DomainPurpose, SignatureScheme};

/// Port of pytest `test_key_event::test_single_domain` (resharing flows).
///
/// Tests expanding and shrinking the participant set through resharing,
/// verifying liveness after each round.
///
/// The Python test additionally covers:
/// - Re-adding a previously dropped node (resharing 3+4)
/// - `reserve_key_event_attempt` / attempt_id assertions
/// These require the restarted MPC node to rejoin the P2P mesh and participate
/// in the resharing protocol, which currently times out. See TODO below.
// TODO: Add resharing rounds 3 (re-add node) and 4 (threshold increase) once
// the MPC node reliably rejoins the resharing protocol after restart.
#[tokio::test]
async fn test_key_resharing() {
    let (cluster, running) = common::setup_cluster(common::KEY_RESHARING_PORT_SEED, |c| {
        c.num_nodes = 4;
        c.initial_participants = 2;
        c.triples_to_buffer = 2;
        c.presignatures_to_buffer = 2;
    })
    .await;

    // Verify initial state: 2 participants, threshold 2.
    assert_eq!(running.parameters.participants.participants.len(), 2);

    // Send sign + CKD requests to verify liveness.
    send_sign_request(&cluster, &running).await;
    send_ckd_request(&cluster, &running).await;

    // Resharing 1: expand from 2 → 4 nodes, threshold 3.
    tracing::info!("resharing 1: expanding to 4 nodes, threshold 3");
    cluster
        .start_resharing(&[0, 1, 2, 3], 3)
        .await
        .expect("resharing 1 failed");
    let running = get_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 4);
    send_sign_request(&cluster, &running).await;
    send_ckd_request(&cluster, &running).await;

    // Resharing 2: shrink to nodes [1,2,3] (drop node 0), threshold 3.
    tracing::info!("resharing 2: dropping node 0");
    cluster
        .start_resharing(&[1, 2, 3], 3)
        .await
        .expect("resharing 2 failed");
    let running = get_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 3);
    send_sign_request(&cluster, &running).await;
    send_ckd_request(&cluster, &running).await;
}

async fn get_running_state(
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
