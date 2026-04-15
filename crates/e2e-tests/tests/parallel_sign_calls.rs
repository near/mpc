use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::{Curve, DomainConfig, DomainId, DomainPurpose};
use serde_json::json;

/// 9 parallel calls (3 robust ECDSA + 2 ECDSA + 2 EdDSA + 2 CKD) via the test parallel
/// contract, against a 6-node / threshold-5 cluster that carries all four signing-scheme
/// domains. Verifies all calls succeed and both the signature and CKD queues drain.
#[tokio::test]
async fn mpc_cluster_should_successfully_process_robust_ecdsa_and_mixed_parallel_requests() {
    const ROBUST_ECDSA_CALLS: u64 = 3;
    const ECDSA_CALLS: u64 = 2;
    const EDDSA_CALLS: u64 = 2;
    const CKD_CALLS: u64 = 2;
    const N: u64 = ROBUST_ECDSA_CALLS + ECDSA_CALLS + EDDSA_CALLS + CKD_CALLS;

    // given
    let (cluster, _running) = common::setup_cluster(common::PARALLEL_SIGN_CALLS_PORT_SEED, |c| {
        c.num_nodes = 6;
        c.initial_participant_indices = (0..6).collect();
        c.threshold = 5;
        c.domains = vec![
            DomainConfig {
                id: DomainId(0),
                curve: Curve::V2Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(2),
                curve: Curve::Edwards25519,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(3),
                curve: Curve::Bls12381,
                purpose: DomainPurpose::CKD,
            },
        ];
        c.presignatures_to_buffer = 6;
    })
    .await;

    let wasm = common::load_parallel_contract_wasm();
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

    let initial_sig_attempts =
        common::sum_metric(&cluster, metrics::SIGNATURES_QUEUE_ATTEMPTS).await;
    let initial_ckd_attempts = common::sum_metric(&cluster, metrics::CKDS_QUEUE_ATTEMPTS).await;

    // when — fire 3 robust ECDSA + (2 ECDSA + 2 EdDSA + 2 CKD) across two concurrent
    // transactions. All 9 in one tx would exhaust the 300 TGas per-transaction cap
    // (9 × 30 TGas per sub-call + 10 TGas callback leaves no gas for the entrypoint).
    // Domains: 0=V2Secp256k1(Sign), 1=Secp256k1(Sign), 2=Edwards25519(Sign), 3=Bls12381(CKD).
    let (robust_result, mixed_result) = tokio::join!(
        parallel_contract.call(
            "make_parallel_sign_calls",
            json!({
                "target_contract": cluster.contract.contract_id(),
                "robust_ecdsa_calls_by_domain": { "0": ROBUST_ECDSA_CALLS },
                "seed": 42u64,
            }),
        ),
        parallel_contract.call(
            "make_parallel_sign_calls",
            json!({
                "target_contract": cluster.contract.contract_id(),
                "ecdsa_calls_by_domain": { "1": ECDSA_CALLS },
                "eddsa_calls_by_domain": { "2": EDDSA_CALLS },
                "ckd_calls_by_domain": { "3": CKD_CALLS },
                "seed": 43u64,
            }),
        ),
    );
    let robust_outcome = robust_result.expect("robust parallel call failed");
    let mixed_outcome = mixed_result.expect("mixed parallel call failed");

    // then
    let robust_completed: u64 = robust_outcome
        .json()
        .expect("failed to parse robust handle_results return value");
    let mixed_completed: u64 = mixed_outcome
        .json()
        .expect("failed to parse mixed handle_results return value");
    let completed = robust_completed + mixed_completed;
    assert_eq!(
        completed, N,
        "expected {N} completed calls, got {completed} ({robust_completed} robust + {mixed_completed} mixed)"
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

    let sig_attempts_delta = common::sum_metric(&cluster, metrics::SIGNATURES_QUEUE_ATTEMPTS).await
        - initial_sig_attempts;
    let ckd_attempts_delta =
        common::sum_metric(&cluster, metrics::CKDS_QUEUE_ATTEMPTS).await - initial_ckd_attempts;
    let total_delta = sig_attempts_delta + ckd_attempts_delta;

    assert!(
        total_delta >= N as i64,
        "expected >= {N} total leader attempts across all nodes and queues, got {total_delta}"
    );
}
