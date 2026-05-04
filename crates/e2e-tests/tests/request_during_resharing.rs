use crate::common;

use mpc_primitives::domain::{Curve, DomainId};
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ProtocolContractState,
};
use rand::SeedableRng;

/// Tests that signature and CKD requests are processed using the previous
/// running state's threshold while resharing is in progress.
///
/// Setup: 6 nodes, 5 initial participants (threshold 5). Domains cover
/// classic ECDSA (CaitSith), robust ECDSA (DamgardEtAl), EdDSA (Frost) and
/// CKD (ConfidentialKeyDerivation). Threshold is 5 because robust ECDSA
/// requires ≥ 5 signers (see `robust_ecdsa::translate_threshold`). Begin
/// resharing to all 6 with threshold 6, then kill node 5 so resharing can't
/// complete. Requests should still succeed using the old threshold of 5
/// across all signing schemes.
#[tokio::test]
async fn test_request_during_resharing() {
    // given
    let (mut cluster, contract_state) =
        common::must_setup_cluster(common::REQUEST_DURING_RESHARING_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participant_indices = (0..5).collect();
            c.threshold = 5;
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
            c.domains.push(DomainConfig {
                id: DomainId(c.domains.len() as u64),
                curve: Curve::Secp256k1,
                protocol: Protocol::DamgardEtAl,
                purpose: DomainPurpose::Sign,
            });
        })
        .await;

    // when
    tracing::info!("beginning resharing to 6 nodes, threshold 6");
    cluster
        .start_resharing(&[0, 1, 2, 3, 4, 5], 6)
        .await
        .expect("start_resharing failed");

    tracing::info!("killing node 5 to block resharing");
    cluster.kill_nodes(&[5]).expect("failed to kill node 5");

    // then
    let ecdsa_domain = contract_state
        .domains
        .domains
        .iter()
        .find(|d| {
            d.curve == Curve::Secp256k1
                && d.protocol == Protocol::CaitSith
                && d.purpose == DomainPurpose::Sign
        })
        .expect("no CaitSith Sign domain");
    let robust_ecdsa_domain = contract_state
        .domains
        .domains
        .iter()
        .find(|d| d.protocol == Protocol::DamgardEtAl && d.purpose == DomainPurpose::Sign)
        .expect("no DamgardEtAl Sign domain");
    let eddsa_domain = contract_state
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Edwards25519 && d.purpose == DomainPurpose::Sign)
        .expect("no Edwards25519 Sign domain");
    let ckd_domain = contract_state
        .domains
        .domains
        .iter()
        .find(|d| d.purpose == DomainPurpose::CKD)
        .expect("no CKD domain");

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for i in 0..3 {
        for (label, domain_id, is_eddsa) in [
            ("ECDSA", ecdsa_domain.id, false),
            ("robust ECDSA", robust_ecdsa_domain.id, false),
            ("EdDSA", eddsa_domain.id, true),
        ] {
            let payload = if is_eddsa {
                common::generate_eddsa_payload(&mut rng)
            } else {
                common::generate_ecdsa_payload(&mut rng)
            };
            tracing::info!(i, label, "sending sign request during resharing");
            let outcome = cluster
                .send_sign_request(domain_id, payload, cluster.default_user_account())
                .await
                .expect("sign request failed");
            assert!(
                outcome.is_success(),
                "{label} sign request {i} failed: {:?}",
                outcome.failure_message()
            );
        }

        tracing::info!(i, "sending CKD request during resharing");
        let outcome = cluster
            .send_ckd_request(
                ckd_domain.id,
                common::generate_ckd_app_public_key(&mut rng),
                cluster.default_user_account(),
            )
            .await
            .expect("ckd request failed");
        assert!(
            outcome.is_success(),
            "ckd request {i} failed: {:?}",
            outcome.failure_message()
        );
    }

    assert!(
        matches!(
            cluster
                .get_contract_state()
                .await
                .expect("failed to get state"),
            ProtocolContractState::Resharing(_)
        ),
        "expected Resharing after requests"
    );
}
