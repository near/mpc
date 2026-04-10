use std::path::{Path, PathBuf};
use std::time::Duration;

use blstrs::{G1Projective, Scalar};
use e2e_tests::{CLUSTER_WAIT_TIMEOUT, MpcCluster, MpcClusterConfig, metrics};
use group::Group;
use near_mpc_contract_interface::types::{
    CKDAppPublicKey, ProtocolContractState, RunningContractState,
};
use near_mpc_crypto_types::Bls12381G1PublicKey;
use serde_json::json;

pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const SIGN_REQUEST_PER_SCHEME_PORT_SEED: u16 = 1;
pub const WEB_ENDPOINTS_PORT_SEED: u16 = 2;
#[expect(dead_code)]
pub const KEY_RESHARING_PORT_SEED: u16 = 3;
#[expect(dead_code)]
pub const REQUEST_DURING_RESHARING_PORT_SEED: u16 = 4;
pub const SUBMIT_PARTICIPANT_INFO_PORT_SEED: u16 = 5;
#[expect(dead_code)]
pub const CANCELLATION_OF_RESHARING_PORT_SEED: u16 = 6;
pub const ROBUST_ECDSA_PORT_SEED: u16 = 7;

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
