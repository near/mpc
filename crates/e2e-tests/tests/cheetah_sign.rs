//! End-to-end DKG + sign for the Nockchain `FrostCheetah` domain.
//!
//! Stands up a local MPC cluster with a `FrostCheetah` domain, lets the
//! node(s) run distributed key generation for it, then submits a sign request
//! and asserts a Cheetah signature comes back. The contract verifies the Cheetah
//! signature on-chain in `respond` before returning it, so a successful
//! `SignatureResponse::Cheetah` is proof the threshold signature is valid.

use crate::common;

use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ProtocolContractState, PublicKey,
    PublicKeyExtended, ReconstructionThreshold, SignatureResponse,
};

#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_dkg_and_sign_frost_cheetah() {
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
    let SignatureResponse::Cheetah { signature } = signature else {
        panic!("expected a Cheetah signature, got {signature:?}")
    };

    let sig_vec: Vec<u8> = serde_json::from_value(
        serde_json::to_value(&signature).expect("serialize CheetahSignature"),
    )
    .expect("CheetahSignature serializes as a byte array");
    let sig: [u8; 64] = sig_vec
        .try_into()
        .expect("CheetahSignature is 64 bytes (c ‖ s)");
    tracing::info!("FrostCheetah MPC threshold signature returned + verified on-chain");

    let state = cluster
        .contract
        .state()
        .await
        .expect("fetch contract state");
    let ProtocolContractState::Running(rs) = state else {
        panic!("expected Running state")
    };
    let root_pk: [u8; 97] = rs
        .keyset
        .domains
        .iter()
        .find(|k| k.domain_id == cheetah_domain.id)
        .map(|k| match &k.key {
            PublicKeyExtended::Cheetah { public_key } => match public_key {
                PublicKey::Cheetah(pk) => pk.0,
                other => panic!("expected a Cheetah public key, got {other:?}"),
            },
            other => panic!("expected a Cheetah extended key, got {other:?}"),
        })
        .expect("FrostCheetah key present in the keyset");

    let root_hex = hex::encode(root_pk);
    let c_hex = hex::encode(&sig[0..32]);
    let s_hex = hex::encode(&sig[32..64]);
    let predecessor = cluster.default_user_account().to_string();

    // web client verify
    let out = std::process::Command::new("node")
        .arg("../chainsig.js/__tests__/nockchain/cheetah-verify.mjs")
        .args([
            root_hex.as_str(),
            predecessor.as_str(),
            "test",
            c_hex.as_str(),
            s_hex.as_str(),
            "11,22,33,44,55",
        ])
        .output()
        .expect("failed to spawn the web client verifier");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    tracing::info!(%stdout, %stderr, "chainsig adapter (rose-ts) verifier output");
    assert!(
        out.status.success() && stdout.contains("VERIFY_OK"),
        "chainsig.js adapter failed to verify the cluster signature against its derived key:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    tracing::info!(
        "✅ cluster Cheetah signature verifies against the chainsig-adapter-derived child key"
    );
}
