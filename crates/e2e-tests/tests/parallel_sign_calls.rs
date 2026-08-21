use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use test_parallel_contract::interface::ParallelContractInterface;

/// 9 parallel calls (3 DamgardEtAl + 2 ECDSA + 2 EdDSA + 2 CKD) via the test parallel
/// contract, against a 6-node / threshold-5 cluster that carries all four signing-scheme
/// domains. Verifies all calls succeed and both the signature and CKD queues drain.
#[tokio::test]
async fn mpc_cluster_should_successfully_process_parallel_requests() {
    const ROBUST_ECDSA_CALLS: u64 = 3;
    const ECDSA_CALLS: u64 = 2;
    const EDDSA_CALLS: u64 = 2;
    const CKD_CALLS: u64 = 2;
    const N: u64 = ROBUST_ECDSA_CALLS + ECDSA_CALLS + EDDSA_CALLS + CKD_CALLS;

    // given
    let (cluster, _running) =
        common::must_setup_cluster(common::PARALLEL_SIGN_CALLS_PORT_SEED, |c| {
            c.num_nodes = 6;
            c.initial_participant_indices = (0..6).collect();
            c.threshold = 5;
            c.domains = vec![
                common::damgard_etal_domain(0, 3),
                DomainConfig {
                    id: DomainId(1),
                    protocol: Protocol::CaitSith,
                    reconstruction_threshold: ReconstructionThreshold::new(5),
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(2),
                    protocol: Protocol::Frost,
                    reconstruction_threshold: ReconstructionThreshold::new(5),
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(3),
                    protocol: Protocol::ConfidentialKeyDerivation,
                    reconstruction_threshold: ReconstructionThreshold::new(5),
                    purpose: DomainPurpose::CKD,
                },
            ];
            c.presignatures_to_buffer = 6;
        })
        .await;

    let wasm = common::must_load_parallel_contract_wasm();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0xABu8; 32]);
    let parallel_contract = cluster
        .blockchain
        .create_account_and_deploy("parallel.sandbox", 10, &key, &wasm)
        .await
        .expect("failed to deploy parallel contract");

    cluster
        .wait_for_metric_all_nodes(
            metrics::SIGNATURES_QUEUE_SIZE,
            |v| v == 0,
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .expect("signature queue not idle before test");
    cluster
        .wait_for_metric_all_nodes(metrics::CKDS_QUEUE_SIZE, |v| v == 0, CLUSTER_WAIT_TIMEOUT)
        .await
        .expect("CKD queue not idle before test");

    let initial_sig_attempts = common::sum_metric(&cluster, metrics::SIGNATURES_QUEUE_ATTEMPTS)
        .await
        .expect("failed to sum signature queue attempts");
    let initial_ckd_attempts = common::sum_metric(&cluster, metrics::CKDS_QUEUE_ATTEMPTS)
        .await
        .expect("failed to sum CKD queue attempts");

    // when — fire all 9 calls in a single transaction
    let outcome = ParallelContractInterface::new(
        parallel_contract.client(),
        parallel_contract.account_id().clone(),
    )
    .make_parallel_sign_calls(
        cluster.contract.account_id().clone(),
        [
            (DomainId(0), Protocol::DamgardEtAl, ROBUST_ECDSA_CALLS),
            (DomainId(1), Protocol::CaitSith, ECDSA_CALLS),
            (DomainId(2), Protocol::Frost, EDDSA_CALLS),
            (DomainId(3), Protocol::ConfidentialKeyDerivation, CKD_CALLS),
        ],
        42,
    )
    .await
    .expect("parallel call failed");

    // then
    let completed: u64 = outcome
        .json()
        .expect("failed to parse handle_results return value");
    assert_eq!(
        completed, N,
        "expected {N} completed calls, got {completed}"
    );

    cluster
        .wait_for_metric_all_nodes(
            metrics::SIGNATURES_QUEUE_SIZE,
            |v| v == 0,
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .expect("signature queue did not drain");
    cluster
        .wait_for_metric_all_nodes(metrics::CKDS_QUEUE_SIZE, |v| v == 0, CLUSTER_WAIT_TIMEOUT)
        .await
        .expect("CKD queue did not drain");

    let sig_attempts_delta = common::sum_metric(&cluster, metrics::SIGNATURES_QUEUE_ATTEMPTS)
        .await
        .expect("failed to sum signature queue attempts")
        - initial_sig_attempts;
    let ckd_attempts_delta = common::sum_metric(&cluster, metrics::CKDS_QUEUE_ATTEMPTS)
        .await
        .expect("failed to sum CKD queue attempts")
        - initial_ckd_attempts;
    let total_delta = sig_attempts_delta + ckd_attempts_delta;

    assert!(
        total_delta >= N as i64,
        "expected >= {N} total leader attempts across all nodes and queues, got {total_delta}"
    );
}
