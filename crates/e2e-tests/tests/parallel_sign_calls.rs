use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, metrics};
use near_mpc_contract_interface::types::{Curve, DomainConfig, DomainId, DomainPurpose};
use serde_json::json;

/// 3 parallel robust ECDSA (V2Secp256k1) sign calls via the test parallel contract.
/// Verifies all calls succeed and the signature queue processes all requests.
#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_successfully_process_parallel_robust_ecdsa_requests() {
    const N: u64 = 3;

    // given
    let (cluster, _running) = common::setup_cluster(common::ROBUST_ECDSA_PARALLEL_PORT_SEED, |c| {
        c.num_nodes = 6;
        c.initial_participant_indices = (0..6).collect();
        c.threshold = 5;
        c.domains = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::V2Secp256k1,
            purpose: DomainPurpose::Sign,
        }];
        c.triples_to_buffer = 0;
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

    let initial_attempts = common::sum_metric(&cluster, metrics::SIGNATURES_QUEUE_ATTEMPTS).await;

    // when
    let outcome = parallel_contract
        .call(
            "make_parallel_sign_calls",
            json!({
                "target_contract": cluster.contract.contract_id(),
                "robust_ecdsa_calls_by_domain": { "0": N },
                "seed": 42u64,
            }),
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
        .expect("signature queue did not drain after parallel calls");

    let attempts_delta =
        common::sum_metric(&cluster, metrics::SIGNATURES_QUEUE_ATTEMPTS).await - initial_attempts;
    assert!(
        attempts_delta >= N as i64,
        "expected >= {N} total leader attempts across all nodes, got {attempts_delta}"
    );
}

/// 6 parallel calls (2 ECDSA + 2 EdDSA + 2 CKD) via the test parallel contract.
/// Verifies all calls succeed and both the signature and CKD queues process all requests.
#[tokio::test]
#[expect(non_snake_case)]
async fn mpc_cluster__should_successfully_process_mixed_parallel_requests() {
    const N: u64 = 6;
    const PER_TYPE: u64 = N / 3; // 2 of each

    // given
    let (cluster, _running) =
        common::setup_cluster(common::PARALLEL_SIGN_CALLS_PORT_SEED, |_| {}).await;

    let wasm = common::load_parallel_contract_wasm();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0xACu8; 32]);
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

    // when — fire 2 ECDSA + 2 EdDSA + 2 CKD in a single transaction.
    // Default domains: 0=Secp256k1(Sign), 1=Ed25519(Sign), 2=Bls12381(CKD).
    let outcome = parallel_contract
        .call(
            "make_parallel_sign_calls",
            json!({
                "target_contract": cluster.contract.contract_id(),
                "ecdsa_calls_by_domain": { "0": PER_TYPE },
                "eddsa_calls_by_domain": { "1": PER_TYPE },
                "ckd_calls_by_domain": { "2": PER_TYPE },
                "seed": 43u64,
            }),
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
