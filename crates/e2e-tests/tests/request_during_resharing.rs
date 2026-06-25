use crate::common::{
    REQUEST_DURING_RESHARING_PORT_SEED, damgard_etal_domain, generate_ckd_app_public_key,
    generate_ecdsa_payload, generate_eddsa_payload, must_get_domain, must_setup_cluster,
};

use near_mpc_contract_interface::types::{Protocol, ProtocolContractState};
use rand::SeedableRng;

/// Tests that signature and CKD requests are processed using the previous
/// running state's threshold while resharing is in progress.
///
/// Setup: 6 nodes, 5 initial participants (threshold 5). Domains cover
/// classic ECDSA (CaitSith), DamgardEtAl, EdDSA (Frost) and
/// CKD (ConfidentialKeyDerivation). The DamgardEtAl domain uses a
/// reconstruction threshold of `t = 3`, which requires `2t - 1 = 5` signers,
/// so we need at least 5 participants. Begin resharing to all 6 with threshold
/// 6, then kill node 5 so resharing can't complete. Requests should still
/// succeed using the previous running state across all signing schemes.
#[tokio::test]
async fn test_request_during_resharing() {
    // given
    let (mut cluster, contract_state) =
        must_setup_cluster(REQUEST_DURING_RESHARING_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participant_indices = (0..5).collect();
            c.threshold = 5;
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
            c.domains
                .push(damgard_etal_domain(c.domains.len() as u64, 3));
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
    let ecdsa_domain = must_get_domain(&contract_state, Protocol::CaitSith);
    let robust_ecdsa_domain = must_get_domain(&contract_state, Protocol::DamgardEtAl);
    let eddsa_domain = must_get_domain(&contract_state, Protocol::Frost);
    let ckd_domain = must_get_domain(&contract_state, Protocol::ConfidentialKeyDerivation);

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for i in 0..3 {
        for (label, domain_id, is_eddsa) in [
            ("ECDSA", ecdsa_domain.id, false),
            ("robust ECDSA", robust_ecdsa_domain.id, false),
            ("EdDSA", eddsa_domain.id, true),
        ] {
            let payload = if is_eddsa {
                generate_eddsa_payload(&mut rng)
            } else {
                generate_ecdsa_payload(&mut rng)
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
                generate_ckd_app_public_key(&mut rng),
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
