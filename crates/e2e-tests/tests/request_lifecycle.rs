mod common;

use near_mpc_contract_interface::types::{DomainPurpose, SignatureResponse, SignatureScheme};
use rand::SeedableRng;

#[tokio::test]
async fn test_request_lifecycle() {
    let (cluster, running) =
        common::setup_cluster(common::REQUEST_LIFECYCLE_PORT_SEED, |_| {}).await;

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
