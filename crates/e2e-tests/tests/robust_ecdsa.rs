mod common;

use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, SignatureResponse, SignatureScheme,
};
use rand::SeedableRng;

/// Tests that V2Secp256k1 (robust ECDSA) signing works end-to-end.
///
/// Setup: 6 nodes, threshold 5, single V2Secp256k1 domain, no triples
/// (robust ECDSA doesn't need them), 6 presignatures buffered.
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

    let v2_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.scheme == SignatureScheme::V2Secp256k1)
        .expect("no V2Secp256k1 domain found");

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for i in 0..3 {
        tracing::info!(i, "sending V2Secp256k1 sign request");
        let outcome = cluster
            .send_sign_request(v2_domain.id, common::generate_ecdsa_payload(&mut rng))
            .await
            .expect("sign request transaction failed");

        assert!(
            outcome.is_success(),
            "sign request {i} failed: {:?}",
            outcome.failure_message()
        );

        let signature: SignatureResponse = outcome
            .json()
            .expect("failed to deserialize SignatureResponse");
        assert!(
            matches!(signature, SignatureResponse::Secp256k1(_)),
            "expected Secp256k1 signature, got: {signature:?}"
        );
        tracing::info!(i, "V2Secp256k1 sign request succeeded");
    }
}
