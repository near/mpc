use crate::common::{
    DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, damgard_etal_domain, generate_ecdsa_payload,
    must_get_domain, must_setup_cluster, wait_metric_on_nodes,
};

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
};
use rand::SeedableRng;

/// Each domain signs under its own reconstruction threshold, not the governance
/// threshold. With 6 nodes and 1 killed, Cait-Sith (needs all 6) can no longer
/// sign while Damgard et al. (needs `2t - 1 = 5`) still can.
#[tokio::test]
#[expect(non_snake_case)]
async fn distinct_reconstruction_thresholds__should_use_per_domain_threshold_when_nodes_are_down() {
    // Given
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let (mut cluster, contract_state) =
        must_setup_cluster(DISTINCT_RECONSTRUCTION_THRESHOLDS_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participant_indices = (0..6).collect();
            c.threshold = 6;
            c.triples_to_buffer = 2;
            c.presignatures_to_buffer = 2;
            c.domains = vec![
                DomainConfig {
                    id: DomainId(0),
                    protocol: Protocol::CaitSith,
                    reconstruction_threshold: ReconstructionThreshold::new(6),
                    purpose: DomainPurpose::Sign,
                },
                damgard_etal_domain(1, 3),
            ];
        })
        .await;

    let caitsith_domain = must_get_domain(&contract_state, Protocol::CaitSith);
    let damgard_domain = must_get_domain(&contract_state, Protocol::DamgardEtAl);

    // When
    cluster.kill_nodes(&[5]).expect("failed to kill node 5");

    // Then Damgard et al. (needs 5 signers) still signs.
    let outcome = cluster
        .send_sign_request(
            damgard_domain.id,
            generate_ecdsa_payload(&mut rng),
            cluster.default_user_account(),
        )
        .await
        .expect("failed to submit Damgard et al. sign request");
    assert!(
        outcome.is_success(),
        "Damgard et al. sign request failed with 5 of 6 nodes alive: {:?}",
        outcome.failure_message()
    );

    // And Cait-Sith (needs all 6) is unanswerable. Its request never resolves on
    // chain, and the yield auto-timeout outlives the JSON-RPC call, so we race the
    // doomed request against the surviving nodes' timeout counter rather than
    // awaiting it (see `timeout_metric.rs`).
    tokio::select! {
        res = wait_metric_on_nodes(
            &cluster,
            &[0, 1, 2, 3, 4],
            metrics::TIMEOUTS_INDEXED,
            |v| v >= 1,
            CLUSTER_WAIT_TIMEOUT,
        ) => res.unwrap_or_else(|_| panic!(
            "{} did not reach 1 on the surviving nodes — Cait-Sith request was answered \
             despite only 5 of its 6 required signers being alive",
            metrics::TIMEOUTS_INDEXED
        )),
        _ = cluster.send_sign_request(
            caitsith_domain.id,
            generate_ecdsa_payload(&mut rng),
            cluster.default_user_account(),
        ) => panic!(
            "Cait-Sith sign request returned before the timeout metric — it should be \
             unanswerable with only 5 of 6 required signers alive"
        ),
    }
}
