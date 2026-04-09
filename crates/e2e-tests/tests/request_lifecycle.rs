mod common;

use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, SignatureResponse, SignatureScheme,
};
use rand::SeedableRng;

#[tokio::test]
async fn test_sign_request_per_scheme() {
    let (cluster, running) =
        common::setup_cluster(common::SIGN_REQUEST_PER_SCHEME_PORT_SEED, |_| {}).await;

    let sign_domains: Vec<_> = running
        .domains
        .domains
        .iter()
        .filter(|d| d.purpose == Some(DomainPurpose::Sign))
        .collect();
    assert!(!sign_domains.is_empty(), "no Sign domains found");

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    // Send a sign request for each Sign domain and verify the signature scheme matches.
    for domain in &sign_domains {
        let payload = match domain.scheme {
            SignatureScheme::Secp256k1 => common::generate_ecdsa_payload(&mut rng),
            SignatureScheme::Ed25519 => common::generate_eddsa_payload(&mut rng),
            _ => continue,
        };

        tracing::info!(domain_id = ?domain.id, scheme = ?domain.scheme, "sending sign request");
        let outcome = cluster
            .send_sign_request(domain.id, payload)
            .await
            .expect("sign request transaction failed");

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
}

#[tokio::test]
async fn test_robust_ecdsa() {
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
    let outcome = cluster
        .send_sign_request(domain.id, common::generate_ecdsa_payload(&mut rng))
        .await
        .expect("sign request transaction failed");

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
