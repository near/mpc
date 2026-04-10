#![expect(non_snake_case)]

use crate::common;

use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, SignatureResponse, SignatureScheme,
};
use rand::SeedableRng;

#[tokio::test]
async fn mpc_cluster__should_sign_with_scheme_matching_domain() {
    // given
    let (cluster, running) =
        common::setup_cluster(common::SIGN_REQUEST_PER_SCHEME_PORT_SEED, |_| {}).await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for domain in &running.domains.domains {
        tracing::info!(domain_id = ?domain.id, purpose = ?domain.purpose, scheme = ?domain.scheme, "sending request");
        match domain.purpose {
            Some(DomainPurpose::Sign) => {
                let payload = match domain.scheme {
                    SignatureScheme::Secp256k1 => common::generate_ecdsa_payload(&mut rng),
                    SignatureScheme::Ed25519 => common::generate_eddsa_payload(&mut rng),
                    _ => continue,
                };

                // when
                let outcome = cluster
                    .send_sign_request(domain.id, payload)
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

                match (&domain.scheme, &signature) {
                    (SignatureScheme::Secp256k1, SignatureResponse::Secp256k1(_)) => {}
                    (SignatureScheme::Ed25519, SignatureResponse::Ed25519 { .. }) => {}
                    _ => panic!(
                        "signature scheme mismatch: requested {:?}, got {:?}",
                        domain.scheme, signature
                    ),
                }
                tracing::info!(domain_id = ?domain.id, "sign request returned valid signature");
            }
            Some(DomainPurpose::CKD) => {
                // when
                let outcome = cluster
                    .send_ckd_request(domain.id, common::generate_ckd_app_public_key(&mut rng))
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
async fn mpc_cluster__should_successfully_process_robust_ecdsa_requests() {
    // given
    let (cluster, running) = common::setup_cluster(common::ROBUST_ECDSA_PORT_SEED, |c| {
        c.num_nodes = 6;
        c.initial_participant_indices = (0..6).collect();
        c.threshold = 5;
        c.domains = vec![DomainConfig {
            id: DomainId(0),
            scheme: SignatureScheme::V2Secp256k1,
            purpose: Some(DomainPurpose::Sign),
        }];
        c.triples_to_buffer = 0;
        c.presignatures_to_buffer = 6;
    })
    .await;

    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.scheme == SignatureScheme::V2Secp256k1)
        .expect("no V2Secp256k1 domain found");

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    // when
    let outcome = cluster
        .send_sign_request(domain.id, common::generate_ecdsa_payload(&mut rng))
        .await
        .expect("sign request transaction failed");

    // then
    assert!(
        outcome.is_success(),
        "V2Secp256k1 sign request failed: {:?}",
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
