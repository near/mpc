use crate::common::{
    DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, generate_ckd_app_public_key,
    generate_ecdsa_payload, generate_eddsa_payload, must_get_domain, must_setup_cluster,
};

use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use rand::SeedableRng;

/// Each domain signs using its own reconstruction threshold rather than the
/// governance threshold. The governance threshold is 4 with a total of 6 nodes.
/// The signing procedure succeeds despite Damgard et al. requiring at least 7
/// participants under a governance-threshold signing model.
/// Therefore, signing is performed using the reconstruction threshold,
/// not the governance threshold.
#[tokio::test]
#[expect(non_snake_case)]
async fn distinct_reconstruction_thresholds__should_sign_for_every_scheme() {
    // Given
    let (cluster, contract_state) =
        must_setup_cluster(DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participant_indices = (0..6).collect();
            c.threshold = 4;
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
            c.domains.push(DomainConfig {
                id: DomainId(c.domains.len() as u64),
                protocol: Protocol::DamgardEtAl,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            });
        })
        .await;

    let ecdsa_domain = must_get_domain(&contract_state, Protocol::CaitSith);
    let robust_ecdsa_domain = must_get_domain(&contract_state, Protocol::DamgardEtAl);
    let eddsa_domain = must_get_domain(&contract_state, Protocol::Frost);
    let ckd_domain = must_get_domain(&contract_state, Protocol::ConfidentialKeyDerivation);

    // When / Then
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for (label, domain_id, is_eddsa) in [
        ("ECDSA", ecdsa_domain.id, false),
        ("robust ECDSA", robust_ecdsa_domain.id, false),
        ("EdDSA", eddsa_domain.id, true),
    ] {
        let payload = if is_eddsa {
            generate_eddsa_payload(&mut rng)
        } else {
            generate_ecdsa_payload(&mut rng)
        };
        let outcome = cluster
            .send_sign_request(domain_id, payload, cluster.default_user_account())
            .await
            .expect("sign request failed");
        assert!(
            outcome.is_success(),
            "{label} sign request failed: {:?}",
            outcome.failure_message()
        );
    }

    let outcome = cluster
        .send_ckd_request(
            ckd_domain.id,
            generate_ckd_app_public_key(&mut rng),
            cluster.default_user_account(),
        )
        .await
        .expect("ckd request failed");
    assert!(
        outcome.is_success(),
        "ckd request failed: {:?}",
        outcome.failure_message()
    );
}
