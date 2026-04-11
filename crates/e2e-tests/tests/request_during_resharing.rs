use crate::common;

use near_mpc_contract_interface::types::{DomainPurpose, ProtocolContractState, SignatureScheme};
use rand::SeedableRng;

/// Tests that signature and CKD requests are processed using the previous
/// running state's threshold while resharing is in progress.
///
/// Setup: 4 nodes, 2 initial participants (threshold 2). Begin resharing to
/// all 4 with threshold 4, then kill node 3 so resharing can't complete.
/// Requests should still succeed using the old threshold of 2.
#[tokio::test]
async fn test_request_during_resharing() {
    // given
    let (mut cluster, running) =
        common::setup_cluster(common::REQUEST_DURING_RESHARING_PORT_SEED, |c| {
            c.num_nodes = 4;
            c.initial_participant_indices = vec![0, 1];
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
        })
        .await;

    // when
    tracing::info!("beginning resharing to 4 nodes, threshold 4");
    cluster
        .start_resharing(&[0, 1, 2, 3], 4)
        .await
        .expect("start_resharing failed");

    tracing::info!("killing node 3 to block resharing");
    cluster.kill_nodes(&[3]).expect("failed to kill node 3");

    // then
    // start_resharing already waited for the contract to enter Resharing state.

    let sign_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.scheme == SignatureScheme::Secp256k1 && d.purpose == Some(DomainPurpose::Sign))
        .expect("no Secp256k1 Sign domain");
    let ckd_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.purpose == Some(DomainPurpose::CKD))
        .expect("no CKD domain");

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    for i in 0..3 {
        tracing::info!(i, "sending sign request during resharing");
        let outcome = cluster
            .send_sign_request(sign_domain.id, common::generate_ecdsa_payload(&mut rng))
            .await
            .expect("sign request failed");
        assert!(
            outcome.is_success(),
            "sign request {i} failed: {:?}",
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
        "expected Resharing after sign requests"
    );

    for i in 0..3 {
        tracing::info!(i, "sending CKD request during resharing");
        let outcome = cluster
            .send_ckd_request(ckd_domain.id, common::generate_ckd_app_public_key(&mut rng))
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
        "expected Resharing after CKD requests"
    );
}
