use std::path::{Path, PathBuf};
use std::time::Duration;

use backon::{ConstantBuilder, Retryable};
use blstrs::{G1Projective, Scalar};
use e2e_tests::{CLUSTER_WAIT_TIMEOUT, MpcCluster, MpcClusterConfig, metrics};
use group::Group;
use near_mpc_contract_interface::types::{
    Bls12381G2PublicKey, CKDAppPublicKey, Curve, DomainId, DomainPurpose, ProtocolContractState,
    PublicKey, PublicKeyExtended, RunningContractState,
};
use near_mpc_crypto_types::Bls12381G1PublicKey;
use serde_json::json;

pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const SIGN_REQUEST_PER_SCHEME_PORT_SEED: u16 = 1;
pub const WEB_ENDPOINTS_PORT_SEED: u16 = 2;
pub const KEY_RESHARING_PORT_SEED: u16 = 3;
pub const REQUEST_DURING_RESHARING_PORT_SEED: u16 = 4;
pub const SUBMIT_PARTICIPANT_INFO_PORT_SEED: u16 = 5;
pub const CANCELLATION_OF_RESHARING_PORT_SEED: u16 = 6;
pub const ROBUST_ECDSA_PORT_SEED: u16 = 7;
pub const PARALLEL_SIGN_CALLS_PORT_SEED: u16 = 8;
pub const CKD_VERIFICATION_PORT_SEED: u16 = 9;
pub const LOST_ASSETS_PORT_SEED: u16 = 10;
pub const CKD_PV_VERIFICATION_PORT_SEED: u16 = 11;
pub const CLEANUP_LAGGING_NODE_PORT_SEED: u16 = 12;
pub const FOREIGN_CHAIN_POLICY_PORT_SEED: u16 = 13;
// 14, 15 reserved for remaining #2889 subtasks (migration_endpoint, migration_service)
pub const FOREIGN_TX_VALIDATION_PORT_SEED: u16 = 16;

/// Start a cluster, wait for Running state and presignatures to buffer.
///
/// Uses `configure` to override defaults (3 nodes, threshold 2, 3 domains).
/// Pass `|_| {}` for defaults.
///
/// ```ignore
/// // Default 3-node cluster:
/// setup_cluster(SEED, |_| {}).await;
///
/// // Custom 4-node cluster with 2 initial participants:
/// setup_cluster(SEED, |c| {
///     c.num_nodes = 4;
///     c.initial_participant_indices = vec![0, 1];
/// }).await;
/// ```
pub async fn setup_cluster(
    port_seed: u16,
    configure: impl FnOnce(&mut MpcClusterConfig),
) -> (MpcCluster, RunningContractState) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,e2e_tests=debug".parse().unwrap()),
        )
        .try_init()
        .ok();

    let contract_wasm = load_contract_wasm();
    let mut config = MpcClusterConfig::default_for_test(port_seed, contract_wasm);
    configure(&mut config);

    let initial_participant_indices = config.participant_indices();
    let presignatures_to_buffer = config.presignatures_to_buffer;
    let cluster = MpcCluster::start(config)
        .await
        .expect("failed to start cluster");

    let protocol_state = cluster
        .wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .expect("cluster did not reach Running state");
    let ProtocolContractState::Running(running) = protocol_state else {
        panic!("expected Running state");
    };

    wait_for_presignatures(
        &cluster,
        &initial_participant_indices,
        presignatures_to_buffer,
    )
    .await;

    (cluster, running)
}

/// Wait until the first `participant_count` nodes each have at least
/// `presignatures_to_buffer` presignatures available.
/// Non-participant nodes are excluded because they don't generate presignatures.
pub async fn wait_for_presignatures(
    cluster: &MpcCluster,
    participant_indices: &[usize],
    presignatures_to_buffer: usize,
) {
    let expected = i64::try_from(presignatures_to_buffer).expect("presignatures exceeds i64::MAX");
    let deadline = tokio::time::Instant::now() + CLUSTER_WAIT_TIMEOUT;
    loop {
        let values = cluster
            .get_metric_all_nodes(metrics::OWNED_PRESIGNATURES_AVAILABLE)
            .await
            .expect("failed to get metrics");
        let participant_values: Vec<_> = participant_indices.iter().map(|&i| values[i]).collect();
        if participant_values
            .iter()
            .all(|v| v.is_some_and(|v| v >= expected))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "participant nodes did not generate presignatures in time (values: {participant_values:?})"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Wait until every node in `indices` reports the given metric satisfying `predicate`.
pub async fn wait_metric_on_nodes(
    cluster: &e2e_tests::MpcCluster,
    indices: &[usize],
    name: &str,
    predicate: impl Fn(i64) -> bool + Copy,
    timeout: std::time::Duration,
) {
    let max_times = (timeout.as_millis() / POLL_INTERVAL.as_millis()) as usize;
    (|| async {
        let values = cluster
            .get_metric_all_nodes(name)
            .await
            .expect("failed to scrape metrics");
        for &idx in indices {
            anyhow::ensure!(
                values[idx].is_some_and(predicate),
                "node {idx}: metric {name} not satisfied (value: {:?})",
                values[idx]
            );
        }
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(POLL_INTERVAL)
            .with_max_times(max_times),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
}

/// Wait until every node in `alive_nodes` is at least `min_height_diff` blocks
/// ahead of `faulty_node` according to the indexer block-height metric.
pub async fn wait_for_indexer_lag(
    cluster: &MpcCluster,
    faulty_node: usize,
    alive_nodes: &[usize],
    min_height_diff: i64,
    timeout: Duration,
) {
    let max_times = (timeout.as_millis() / POLL_INTERVAL.as_millis()) as usize;
    (|| async {
        let heights = cluster
            .get_metric_all_nodes(metrics::INDEXER_LATEST_BLOCK_HEIGHT)
            .await
            .expect("failed to get metrics");
        let faulty = heights[faulty_node].unwrap_or(0);
        for &idx in alive_nodes {
            anyhow::ensure!(
                heights[idx].unwrap_or(0) >= faulty + min_height_diff,
                "node {idx} not yet {min_height_diff} blocks ahead of faulty node (alive={:?}, faulty={faulty})",
                heights[idx],
            );
        }
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(POLL_INTERVAL)
            .with_max_times(max_times),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
}

/// Sum a metric across all running nodes (stopped nodes contribute 0).
pub async fn sum_metric(cluster: &MpcCluster, name: &str) -> i64 {
    cluster
        .get_metric_all_nodes(name)
        .await
        .expect("failed to scrape metrics")
        .into_iter()
        .flatten()
        .sum()
}

pub fn load_contract_wasm() -> Vec<u8> {
    if let Ok(path) = std::env::var("MPC_CONTRACT_WASM") {
        let wasm_path = PathBuf::from(&path);
        return std::fs::read(&wasm_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read contract WASM at {}: {e}",
                wasm_path.display()
            )
        });
    }

    let default_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/near/contract/mpc_contract.wasm");

    if default_path.exists() {
        return std::fs::read(&default_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read contract WASM at {}: {e}",
                default_path.display()
            )
        });
    }

    tracing::info!("MPC_CONTRACT_WASM not set and pre-built WASM not found — building contract");
    test_utils::contract_build::ContractBuilder::new("crates/contract/Cargo.toml").build()
}

pub fn load_parallel_contract_wasm() -> Vec<u8> {
    if let Ok(path) = std::env::var("MPC_PARALLEL_CONTRACT_WASM") {
        let wasm_path = PathBuf::from(&path);
        return std::fs::read(&wasm_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read parallel contract WASM at {}: {e}",
                wasm_path.display()
            )
        });
    }

    let default_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/near/test-parallel-contract/test_parallel_contract.wasm");
    if default_path.exists() {
        return std::fs::read(&default_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read parallel contract WASM at {}: {e}",
                default_path.display()
            )
        });
    }
    tracing::info!("pre-built parallel contract WASM not found — building");
    test_utils::contract_build::ContractBuilder::new("crates/test-parallel-contract/Cargo.toml")
        .build()
}

pub fn generate_ecdsa_payload(rng: &mut impl rand::Rng) -> serde_json::Value {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    json!({ "Ecdsa": hex::encode(bytes) })
}

pub fn generate_eddsa_payload(rng: &mut impl rand::Rng) -> serde_json::Value {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    json!({ "Eddsa": hex::encode(bytes) })
}

pub fn generate_ckd_app_public_key(rng: &mut impl rand::Rng) -> CKDAppPublicKey {
    let point = G1Projective::generator() * Scalar::from(rng.next_u64());
    CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey::from(&point))
}

/// Extract the BLS12381 G2 public key for a given domain from running contract state.
pub fn bls_public_key(running: &RunningContractState, domain_id: DomainId) -> Bls12381G2PublicKey {
    let key_for_domain = running
        .keyset
        .domains
        .iter()
        .find(|k| k.domain_id == domain_id)
        .expect("no key found for BLS12381 domain");
    match &key_for_domain.key {
        PublicKeyExtended::Bls12381 {
            public_key: PublicKey::Bls12381(g2),
        } => g2.clone(),
        other => panic!("expected Bls12381 key, got {other:?}"),
    }
}

pub async fn send_sign_request(
    cluster: &e2e_tests::MpcCluster,
    running: &RunningContractState,
    rng: &mut impl rand::Rng,
    account_id: &near_kit::AccountId,
) {
    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Secp256k1 && d.purpose == DomainPurpose::Sign)
        .expect("no Secp256k1 Sign domain");
    let outcome = cluster
        .send_sign_request(domain.id, generate_ecdsa_payload(rng), account_id)
        .await
        .expect("sign request failed");
    assert!(
        outcome.is_success(),
        "sign request failed: {:?}",
        outcome.failure_message()
    );
}

pub async fn send_ckd_request(
    cluster: &e2e_tests::MpcCluster,
    running: &RunningContractState,
    rng: &mut impl rand::Rng,
    account_id: &near_account_id::AccountId,
) {
    let domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.purpose == DomainPurpose::CKD)
        .expect("no CKD domain");
    let outcome = cluster
        .send_ckd_request(domain.id, generate_ckd_app_public_key(rng), account_id)
        .await
        .expect("ckd request failed");
    assert!(
        outcome.is_success(),
        "ckd request failed: {:?}",
        outcome.failure_message()
    );
}
