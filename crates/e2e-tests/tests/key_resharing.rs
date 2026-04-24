use crate::common;

use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use mpc_primitives::domain::{Curve, DomainId};
use near_mpc_contract_interface::types::{
    AttemptId, DomainConfig, DomainPurpose, ProtocolContractState,
};
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
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

    // Resharing 1: expand from 2 → 4 nodes, threshold 3.
    tracing::info!("resharing 1: expanding to 4 nodes, threshold 3");
    cluster
        .start_resharing_and_wait(&[0, 1, 2, 3], 3)
        .await
        .expect("resharing 1 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 4);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

    // Resharing 2: shrink to nodes [1,2,3] (drop node 0), threshold 3.
    tracing::info!("resharing 2: dropping node 0");
    cluster
        .start_resharing_and_wait(&[1, 2, 3], 3)
        .await
        .expect("resharing 2 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 3);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

    // Resharing 3: add node 4 (has been running and syncing since startup)
    // to replace the dropped node 0. Back to 4 participants, threshold 3.
    tracing::info!("resharing 3: adding node 4 to replace dropped node 0");
    cluster
        .start_resharing_and_wait(&[1, 2, 3, 4], 3)
        .await
        .expect("resharing 3 failed");
    let running = expect_running_state(&cluster).await;
    assert_eq!(running.parameters.participants.participants.len(), 4);
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

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
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
}

/// Port of pytest `test_key_event::test_multi_domain`.
///
/// Starts with 2 nodes and the default 3 domains, adds 4 more domains (total 7),
/// reshares 2→4 with threshold 3, then starts keygen for another domain, kills
/// the leader and votes to cancel. Verifies the cancelled domain is not present
/// in the keyset and `next_domain_id` advances past it.
#[tokio::test]
async fn test_multi_domain() {
    // given: 4 nodes available, 2 initial participants, default 3 domains
    // (Secp256k1 Sign, Edwards25519 Sign, Bls12381 CKD -> next_domain_id = 3).
    let (mut cluster, running) = common::setup_cluster(common::MULTI_DOMAIN_PORT_SEED, |c| {
        c.num_nodes = 4;
        c.initial_participant_indices = (0..2).collect();
        c.triples_to_buffer = 2;
        c.presignatures_to_buffer = 2;
    })
    .await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    assert_eq!(running.domains.next_domain_id, 3);

    // liveness before any changes
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

    // add 4 more domains (IDs 3..=6, next_domain_id = 7)
    tracing::info!("adding 4 additional domains");
    cluster
        .add_domains_and_wait(vec![
            DomainConfig {
                id: DomainId(3),
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(4),
                curve: Curve::Edwards25519,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(5),
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(6),
                curve: Curve::Edwards25519,
                purpose: DomainPurpose::Sign,
            },
        ])
        .await
        .expect("add_domains failed");

    let running = expect_running_state(&cluster).await;
    assert_eq!(running.domains.next_domain_id, 7);
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account()).await;

    // reshare 2 -> 4 nodes, threshold 3
    tracing::info!("resharing to 4 nodes, threshold 3");
    cluster
        .start_resharing_and_wait(&[0, 1, 2, 3], 3)
        .await
        .expect("resharing failed");

    // start keygen for a new domain (ID 7, next_domain_id -> 8), then kill the
    // leader so keygen can't complete. Threshold (3) remaining participants
    // then vote to cancel.
    tracing::info!("starting keygen for new domain, then cancelling");
    cluster
        .start_add_domains(vec![DomainConfig {
            id: DomainId(7),
            curve: Curve::Secp256k1,
            purpose: DomainPurpose::Sign,
        }])
        .await
        .expect("start_add_domains failed");
    cluster.kill_nodes(&[0]).expect("failed to kill node 0");

    for node_idx in [1, 2, 3] {
        let outcome = cluster
            .vote_cancel_keygen_from(node_idx, 8)
            .await
            .expect("failed to send cancel keygen vote");
        assert!(
            outcome.is_success(),
            "cancel keygen vote from node {node_idx} failed: {:?}",
            outcome.failure_message()
        );
    }

    cluster
        .wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .expect("contract did not return to Running after cancellation");

    // then: domain 7 should not be in the keyset, and next_domain_id should be 8
    let running = expect_running_state(&cluster).await;
    assert!(
        !running
            .keyset
            .domains
            .iter()
            .any(|k| k.domain_id == DomainId(7)),
        "cancelled domain 7 should not be in keyset"
    );
    assert_eq!(
        running.domains.next_domain_id, 8,
        "next_domain_id should advance past cancelled domain"
    );
    assert!(
        !running.domains.domains.iter().any(|d| d.id == DomainId(7)),
        "cancelled domain 7 should not be in domain registry"
    );
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
