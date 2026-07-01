use crate::common::{
    DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, damgard_etal_domain, generate_ckd_app_public_key,
    must_get_domain, must_setup_cluster, sign_all_schemes,
};

use near_mpc_contract_interface::types::Protocol;
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
            c.domains
                .push(damgard_etal_domain(c.domains.len() as u64, 3));
        })
        .await;

    let ckd_domain = must_get_domain(&contract_state, Protocol::ConfidentialKeyDerivation);

    // When / Then
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    sign_all_schemes(&cluster, &contract_state, &mut rng).await;

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
