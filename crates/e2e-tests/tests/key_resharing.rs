use crate::common;

use anyhow::{Context, bail};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use mpc_primitives::domain::{Curve, DomainId};
use near_mpc_contract_interface::types::{
    AttemptId, DomainConfig, DomainPurpose, Protocol, ProtocolContractState,
};
use rand::SeedableRng;

/// Tests single-domain key generation and multiple rounds of resharing
/// with participant set changes, verifying liveness after each round.
#[tokio::test]
async fn test_key_resharing() {
    // Start 5 nodes but only 2 as initial participants. Node 4 stays idle
    // (syncing) so it can be used as a fresh replacement when node 0 is dropped.
    let (cluster, running) = common::must_setup_cluster(common::KEY_RESHARING_PORT_SEED, |c| {
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
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");

    // Resharing 1: expand from 2 → 4 nodes, threshold 3.
    tracing::info!("resharing 1: expanding to 4 nodes, threshold 3");
    cluster
        .start_resharing_and_wait(&[0, 1, 2, 3], 3)
        .await
        .expect("resharing 1 failed");
    let running = running_state(&cluster).await.expect("running_state failed");
    assert_eq!(running.parameters.participants.participants.len(), 4);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");

    // Resharing 2: shrink to nodes [1,2,3] (drop node 0), threshold 3.
    tracing::info!("resharing 2: dropping node 0");
    cluster
        .start_resharing_and_wait(&[1, 2, 3], 3)
        .await
        .expect("resharing 2 failed");
    let running = running_state(&cluster).await.expect("running_state failed");
    assert_eq!(running.parameters.participants.participants.len(), 3);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");

    // Resharing 3: add node 4 (has been running and syncing since startup)
    // to replace the dropped node 0. Back to 4 participants, threshold 3.
    tracing::info!("resharing 3: adding node 4 to replace dropped node 0");
    cluster
        .start_resharing_and_wait(&[1, 2, 3, 4], 3)
        .await
        .expect("resharing 3 failed");
    let running = running_state(&cluster).await.expect("running_state failed");
    assert_eq!(running.parameters.participants.participants.len(), 4);
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");

    // Resharing 4: increase threshold to 4 (all participants required).
    tracing::info!("resharing 4: increasing threshold to 4");
    cluster
        .start_resharing_and_wait(&[1, 2, 3, 4], 4)
        .await
        .expect("resharing 4 failed");
    let running = running_state(&cluster).await.expect("running_state failed");
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
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");
}

/// Verifies that `vote_cancel_keygen` rolls back a stalled keygen: the
/// cancelled domain is absent from both the keyset and the domain registry,
/// and `next_domain_id` advances past the skipped id.
#[tokio::test]
async fn test_multi_domain() {
    // given: 4-node cluster reshared to 4 participants at threshold 3, with
    // 7 domains (3 default + 4 added). Liveness verified after each setup stage.
    let (mut cluster, running) = common::must_setup_cluster(common::MULTI_DOMAIN_PORT_SEED, |c| {
        c.num_nodes = 4;
        c.initial_participant_indices = (0..2).collect();
        c.triples_to_buffer = 2;
        c.presignatures_to_buffer = 2;
    })
    .await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    assert_eq!(running.domains.next_domain_id, 3);
    common::send_sign_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("sign request failed");
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");

    cluster
        .add_domains_and_wait(vec![
            DomainConfig {
                id: DomainId(3),
                curve: Curve::Secp256k1,
                protocol: Protocol::CaitSith,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(4),
                curve: Curve::Edwards25519,
                protocol: Protocol::Frost,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(5),
                curve: Curve::Secp256k1,
                protocol: Protocol::CaitSith,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(6),
                curve: Curve::Edwards25519,
                protocol: Protocol::Frost,
                purpose: DomainPurpose::Sign,
            },
        ])
        .await
        .expect("add_domains_and_wait failed");
    let running = running_state(&cluster).await.expect("running_state failed");
    assert_eq!(running.domains.next_domain_id, 7);
    common::send_ckd_request(&cluster, &running, &mut rng, cluster.default_user_account())
        .await
        .expect("ckd request failed");

    cluster
        .start_resharing_and_wait(&[0, 1, 2, 3], 3)
        .await
        .expect("resharing failed");

    // when: start keygen for a new domain (ID 7), kill the leader to stall it,
    // then vote to cancel from the 3 remaining participants.
    cluster
        .start_add_domains(vec![DomainConfig {
            id: DomainId(7),
            curve: Curve::Secp256k1,
            protocol: Protocol::CaitSith,
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

    // then: contract returns to Running, the cancelled domain is absent from
    // both keyset and registry, and next_domain_id has advanced past it.
    cluster
        .wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .expect("contract did not return to Running after cancellation");
    let running = running_state(&cluster).await.expect("running_state failed");
    assert!(
        !running
            .keyset
            .domains
            .iter()
            .any(|k| k.domain_id == DomainId(7)),
        "cancelled domain 7 should not be in keyset"
    );
    assert!(
        !running.domains.domains.iter().any(|d| d.id == DomainId(7)),
        "cancelled domain 7 should not be in domain registry"
    );
    assert_eq!(
        running.domains.next_domain_id, 8,
        "next_domain_id should advance past cancelled domain"
    );
}

async fn running_state(
    cluster: &e2e_tests::MpcCluster,
) -> anyhow::Result<near_mpc_contract_interface::types::RunningContractState> {
    let state = cluster
        .get_contract_state()
        .await
        .context("failed to get state")?;
    match state {
        near_mpc_contract_interface::types::ProtocolContractState::Running(r) => Ok(r),
        other => bail!("expected Running, got: {other:?}"),
    }
}
