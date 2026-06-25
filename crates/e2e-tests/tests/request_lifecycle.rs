use crate::common::{
    ROBUST_ECDSA_PORT_SEED, SIGN_REQUEST_PER_SCHEME_PORT_SEED, generate_ckd_app_public_key,
    generate_ecdsa_payload, generate_eddsa_payload, must_get_domain, must_setup_cluster,
};

use near_mpc_contract_interface::types::{
    Curve, DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
    SignatureResponse,
};
use rand::SeedableRng;

#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_sign_with_scheme_matching_domain() {
    // given
    let (cluster, running) = must_setup_cluster(SIGN_REQUEST_PER_SCHEME_PORT_SEED, |_| {}).await;

    assert!(
        !running.domains.domains.is_empty(),
        "expected at least one domain, got none"
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for domain in &running.domains.domains {
        tracing::info!(domain_id = ?domain.id, purpose = ?domain.purpose, curve = ?Curve::from(domain.protocol), "sending request");
        match domain.purpose {
            DomainPurpose::Sign => {
                let payload = match Curve::from(domain.protocol) {
                    Curve::Secp256k1 => generate_ecdsa_payload(&mut rng),
                    Curve::Edwards25519 => generate_eddsa_payload(&mut rng),
                    _ => continue,
                };

                // when
                let outcome = cluster
                    .send_sign_request(domain.id, payload, cluster.default_user_account())
                    .await
                    .expect("sign request transaction failed");

                // then
                assert!(
                    outcome.is_success(),
                    "sign request for domain {:?} failed: {:?}",
                    domain.id,
                    outcome.failure_message()
                );

                let signature: SignatureResponse = outcome
                    .json()
                    .expect("failed to deserialize SignatureResponse from transaction result");

                let curve = Curve::from(domain.protocol);
                match (curve, &signature) {
                    (Curve::Secp256k1, SignatureResponse::Secp256k1(_)) => {}
                    (Curve::Edwards25519, SignatureResponse::Ed25519 { .. }) => {}
                    _ => panic!(
                        "signature scheme mismatch: requested {:?}, got {:?}",
                        curve, signature
                    ),
                }
                tracing::info!(domain_id = ?domain.id, "sign request returned valid signature");
            }
            DomainPurpose::CKD => {
                // when
                let outcome = cluster
                    .send_ckd_request(
                        domain.id,
                        generate_ckd_app_public_key(&mut rng),
                        cluster.default_user_account(),
                    )
                    .await
                    .expect("ckd request transaction failed");

                // then
                assert!(
                    outcome.is_success(),
                    "ckd request for domain {:?} failed: {:?}",
                    domain.id,
                    outcome.failure_message()
                );
                tracing::info!(domain_id = ?domain.id, "ckd request succeeded");
            }
            _ => continue,
        }
    }
}

#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_successfully_process_robust_ecdsa_requests() {
    // given
    let (cluster, running) = must_setup_cluster(ROBUST_ECDSA_PORT_SEED, |c| {
        c.num_nodes = 6;
        c.initial_participant_indices = (0..6).collect();
        c.threshold = 5;
        c.domains = vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::DamgardEtAl,
            reconstruction_threshold: ReconstructionThreshold::new(3),
            purpose: DomainPurpose::Sign,
        }];
        c.triples_to_buffer = 0;
        c.presignatures_to_buffer = 6;
    })
    .await;

    let domain = must_get_domain(&running, Protocol::DamgardEtAl);

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    // when
    let outcome = cluster
        .send_sign_request(
            domain.id,
            generate_ecdsa_payload(&mut rng),
            cluster.default_user_account(),
        )
        .await
        .expect("sign request transaction failed");

    // then
    assert!(
        outcome.is_success(),
        "DamgardEtAl sign request failed: {:?}",
        outcome.failure_message()
    );

    let signature: SignatureResponse = outcome
        .json()
        .expect("failed to deserialize SignatureResponse");
    assert!(
        matches!(signature, SignatureResponse::Secp256k1(_)),
        "expected Secp256k1 signature, got: {signature:?}"
    );
}
