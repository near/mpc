use crate::common::{
    DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, damgard_etal_domain, generate_ecdsa_payload,
    must_get_domain, must_setup_cluster,
};

use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
};
use rand::SeedableRng;

/// Each domain signs under its own reconstruction threshold, not the governance
/// threshold. With 6 nodes and 1 killed, Cait-Sith (needs all 6) can no longer
/// sign while Damgard et al. (needs `2t - 1 = 5`) still can.
#[tokio::test]
#[expect(non_snake_case)]
async fn distinct_reconstruction_thresholds__should_use_per_domain_threshold_when_nodes_are_down() {
    // Given
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let (mut cluster, contract_state) =
        must_setup_cluster(DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participant_indices = (0..6).collect();
            c.threshold = 6;
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
            c.domains = vec![
                DomainConfig {
                    id: DomainId(0),
                    protocol: Protocol::CaitSith,
                    reconstruction_threshold: ReconstructionThreshold::new(6),
                    purpose: DomainPurpose::Sign,
                },
                damgard_etal_domain(1, 3),
            ];
        })
        .await;

    let caitsith_domain = must_get_domain(&contract_state, Protocol::CaitSith);
    let damgard_domain = must_get_domain(&contract_state, Protocol::DamgardEtAl);

    // When
    cluster.kill_nodes(&[5]).expect("failed to kill node 5");

    // Then Damgard et al. (needs 5 signers) still signs.
    let outcome = cluster
        .send_sign_request(
            damgard_domain.id,
            generate_ecdsa_payload(&mut rng),
            cluster.default_user_account(),
        )
        .await
        .expect("failed to submit Damgard et al. sign request");
    assert!(
        outcome.is_success(),
        "Damgard et al. sign request failed with 5 of 6 nodes alive: {:?}",
        outcome.failure_message()
    );

    // And Cait-Sith (needs all 6) is unanswerable: its request fails on chain once the
    // yield times out, which outlives the JSON-RPC call. So we submit, grab the tx hash
    // once included, then poll the receipt tree to `Final` rather than await it.
    let user = cluster.default_user_account().clone();
    let tx_hash = cluster
        .send_sign_request_included(caitsith_domain.id, generate_ecdsa_payload(&mut rng), &user)
        .await
        .expect("failed to submit Cait-Sith sign request");
    let outcome = cluster
        .wait_sign_request_final(tx_hash, &user, CLUSTER_WAIT_TIMEOUT)
        .await
        .expect("Cait-Sith sign request did not reach a final on-chain outcome");
    assert!(
        outcome.is_failure(),
        "Cait-Sith sign request succeeded with only 5 of its 6 required signers alive"
    );
    let message = outcome.failure_message().unwrap_or_default();
    assert!(
        message.contains("timed out"),
        "Cait-Sith sign request failed for an unexpected reason: {message}"
    );
}
