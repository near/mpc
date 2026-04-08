#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use blstrs::{G1Projective, Scalar};
use e2e_tests::{MpcCluster, MpcClusterConfig};
use group::Group;
use near_mpc_contract_interface::types::{
    CKDAppPublicKey, ProtocolContractState, RunningContractState,
};
use near_mpc_crypto_types::Bls12381G1PublicKey;
use serde_json::json;

pub const REQUEST_LIFECYCLE_PORT_SEED: u16 = 1;
pub const WEB_ENDPOINTS_PORT_SEED: u16 = 2;
pub const KEY_RESHARING_PORT_SEED: u16 = 3;
pub const REQUEST_DURING_RESHARING_PORT_SEED: u16 = 4;
pub const SUBMIT_PARTICIPANT_INFO_PORT_SEED: u16 = 5;
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
///     c.initial_participants = 2;
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

    let initial_participants = config.initial_participants;
    let presignatures_to_buffer = config.presignatures_to_buffer;
    let cluster = MpcCluster::start(config)
        .await
        .expect("failed to start cluster");

    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get contract state");
    let running = match state {
        ProtocolContractState::Running(r) => r,
        other => panic!("expected Running state, got: {other:?}"),
    };

    // Only wait for presignatures on initial participant nodes —
    // non-participant nodes don't generate presignatures.
    let expected = i64::try_from(presignatures_to_buffer).expect("presignatures exceeds i64::MAX");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let values = cluster
            .get_metric_all_nodes("mpc_owned_num_presignatures_available")
            .await
            .expect("failed to get metrics");
        let participant_values: Vec<_> = values.iter().take(initial_participants).collect();
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
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    (cluster, running)
}

pub fn load_contract_wasm() -> Vec<u8> {
    let wasm_path: PathBuf = std::env::var("MPC_CONTRACT_WASM")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm")
        });

    std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read contract WASM at {}: {e}\n\
             Build it first:\n  \
             cargo build -p mpc-contract --target=wasm32-unknown-unknown \
             --profile=release-contract --locked\n  \
             wasm-opt -Oz <path> -o <path>",
            wasm_path.display()
        )
    })
}

pub fn generate_ecdsa_payload() -> serde_json::Value {
    let bytes: [u8; 32] = rand::random();
    json!({ "Ecdsa": hex::encode(bytes) })
}

pub fn generate_eddsa_payload() -> serde_json::Value {
    let bytes: [u8; 32] = rand::random();
    json!({ "Eddsa": hex::encode(bytes) })
}

pub fn generate_ckd_app_public_key() -> CKDAppPublicKey {
    let point = G1Projective::generator() * Scalar::from(42u64);
    CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey::from(&point))
}
