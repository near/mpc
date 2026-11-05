use crate::common::{
    MAINNET_PROTOCOL_PORT_SEED, generate_ckd_app_public_key, must_get_payload_for_domain,
    must_setup_cluster,
};

use near_mpc_contract_interface::types::DomainPurpose;
use rand::{SeedableRng, rngs::StdRng};

#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_serve_requests_at_mainnet_protocol_version() {
    // Given
    let (cluster, running) = must_setup_cluster(MAINNET_PROTOCOL_PORT_SEED, |c| {
        c.sandbox_protocol_version = Some(test_utils::MAINNET_PROTOCOL_VERSION);
    })
    .await;
    let mut rng = StdRng::seed_from_u64(0);

    for domain in &running.domains.domains {
        // When
        let outcome = match domain.purpose {
            DomainPurpose::Sign => cluster
                .send_sign_request(
                    domain.id,
                    must_get_payload_for_domain(domain, &mut rng),
                    cluster.default_user_account(),
                )
                .await
                .expect("sign request transaction failed"),
            DomainPurpose::CKD => cluster
                .send_ckd_request(
                    domain.id,
                    generate_ckd_app_public_key(&mut rng),
                    cluster.default_user_account(),
                )
                .await
                .expect("ckd request transaction failed"),
            _ => continue,
        };

        // Then
        assert!(
            outcome.is_success(),
            "request for domain {:?} failed: {:?}",
            domain.id,
            outcome.failure_message()
        );
    }
}
