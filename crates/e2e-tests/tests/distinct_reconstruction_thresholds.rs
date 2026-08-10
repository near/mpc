use crate::common::{
    DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, ckd_domain, damgard_etal_domain,
    generate_ckd_app_public_key, generate_ecdsa_payload, generate_eddsa_payload, must_get_domain,
    must_setup_cluster,
};

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, WithTimeout};
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold, SignRequestArgs,
};
use rand::{SeedableRng, rngs::StdRng};

/// Each domain signs under its own reconstruction threshold, not the governance
/// threshold. With 6 nodes and 1 killed, Cait-Sith (needs all 6) can no longer sign
/// while Damgard et al. (`2t - 1 = 5`), CKD (`t = 5`) and Frost (`t = 5`) still can.
#[tokio::test]
#[expect(non_snake_case)]
async fn distinct_reconstruction_thresholds__should_use_per_domain_threshold_when_nodes_are_down() {
    // Given
    let mut rng = StdRng::seed_from_u64(0);
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
                ckd_domain(2, 5),
                DomainConfig {
                    id: DomainId(3),
                    protocol: Protocol::Frost,
                    reconstruction_threshold: ReconstructionThreshold::new(5),
                    purpose: DomainPurpose::Sign,
                },
            ];
        })
        .await;

    let caitsith_domain = must_get_domain(&contract_state, Protocol::CaitSith);
    let damgard_domain = must_get_domain(&contract_state, Protocol::DamgardEtAl);
    let ckd_domain = must_get_domain(&contract_state, Protocol::ConfidentialKeyDerivation);
    let frost_domain = must_get_domain(&contract_state, Protocol::Frost);

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

    // And CKD (its own `t = 5`, not the governance threshold of 6) still derives.
    let outcome = cluster
        .send_ckd_request(
            ckd_domain.id,
            generate_ckd_app_public_key(&mut rng),
            cluster.default_user_account(),
        )
        .await
        .expect("failed to submit CKD request");
    assert!(
        outcome.is_success(),
        "CKD request failed with 5 of its 5 required signers alive: {:?}",
        outcome.failure_message()
    );

    // And Frost (its own `t = 5`) still signs.
    let outcome = cluster
        .send_sign_request(
            frost_domain.id,
            generate_eddsa_payload(&mut rng),
            cluster.default_user_account(),
        )
        .await
        .expect("failed to submit Frost sign request");
    assert!(
        outcome.is_success(),
        "Frost sign request failed with 5 of its 5 required signers alive: {:?}",
        outcome.failure_message()
    );

    // Cait-Sith needs all 6, so its yield runs to the on-chain timeout — past the RPC's
    // wait window, hence the deadline.
    let outcome = cluster
        .contract_handle(cluster.default_user_account())
        .with_timeout(CLUSTER_WAIT_TIMEOUT)
        .sign(SignRequestArgs {
            path: "test".to_string(),
            payload: generate_ecdsa_payload(&mut rng),
            domain_id: caitsith_domain.id,
        })
        .await
        .expect("Cait-Sith sign request did not reach an on-chain outcome");
    assert!(
        outcome.is_failure(),
        "Cait-Sith sign request succeeded with only 5 of its 6 required signers alive"
    );
    let message = outcome.failure_message().unwrap_or_default();
    assert!(
        message.contains("Request has timed out."),
        "Cait-Sith sign request failed for an unexpected reason: {message}"
    );
}
