//! End-to-end DKG + sign for the Nockchain `FrostCheetah` domain.
//!
//! Stands up a local MPC cluster whose only domain is `FrostCheetah`, lets the
//! node(s) run distributed key generation for it, then submits a sign request
//! and asserts a Cheetah signature comes back. The contract verifies the Cheetah
//! signature on-chain in `respond` before returning it, so a successful
//! `SignatureResponse::Cheetah` is proof the threshold signature is valid.

use crate::common;

use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold, SignatureResponse,
};

#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_dkg_and_sign_frost_cheetah() {
    // given: a single-node cluster whose only domain is FrostCheetah.
    // The contract enforces a minimum absolute threshold (≥2), so a true 1-of-1
    // is rejected; use the smallest real threshold cluster: 2-of-2.
    // FROST/Cheetah signing generates nonces per request and doesn't use
    // ECDSA-style pre-buffered presignatures — but `must_setup_cluster` waits for
    // presignature buffering after DKG, and that metric is absent (None) on a
    // Schnorr-only cluster. Include a CaitSith (ECDSA) domain so presignatures
    // generate and the harness wait passes; we still sign on the FrostCheetah one.
    let (cluster, running) = common::must_setup_cluster(30, |c| {
        c.num_nodes = 2;
        c.threshold = 2;
        c.domains = vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                protocol: Protocol::FrostCheetah,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ];
    })
    .await;

    // DKG for the FrostCheetah domain completed during cluster setup.
    let cheetah_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.protocol == Protocol::FrostCheetah)
        .expect("FrostCheetah domain present after DKG");
    tracing::info!(domain_id = ?cheetah_domain.id, "FrostCheetah DKG complete");

    // Nockchain Tip5 sign payload: a 5-belt digest as 40 little-endian bytes,
    // submitted through the Eddsa byte-payload variant (the contract accepts
    // `payload.as_eddsa()` for a FrostCheetah domain).
    let digest: [u64; 5] = [11, 22, 33, 44, 55];
    let mut digest_bytes = [0u8; 40];
    for (chunk, &belt) in digest_bytes.chunks_mut(8).zip(&digest) {
        chunk.copy_from_slice(&belt.to_le_bytes());
    }
    let payload = serde_json::json!({ "Eddsa": hex::encode(digest_bytes) });

    // when: request a signature through the MPC cluster.
    let outcome = cluster
        .send_sign_request(cheetah_domain.id, payload, cluster.default_user_account())
        .await
        .expect("cheetah sign request transaction failed");
    assert!(
        outcome.is_success(),
        "cheetah sign request failed: {:?}",
        outcome.failure_message()
    );

    // then: a Cheetah signature is returned (contract already verified it on-chain).
    let signature: SignatureResponse = outcome
        .json()
        .expect("failed to deserialize SignatureResponse");
    match signature {
        SignatureResponse::Cheetah { signature } => {
            tracing::info!(?signature, "FrostCheetah MPC threshold signature returned + verified on-chain");
        }
        other => panic!("expected a Cheetah signature, got {other:?}"),
    }
}
