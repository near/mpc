use std::path::{Path, PathBuf};
use std::time::Duration;

use e2e_tests::{MpcCluster, MpcClusterConfig};
use near_mpc_contract_interface::types::{
    DomainPurpose, ProtocolContractState, SignatureResponse, SignatureScheme,
};
use serde_json::json;

/// Load the pre-built MPC contract WASM.
///
/// Uses `MPC_CONTRACT_WASM` env var if set, otherwise falls back to the
/// default cargo build output path. The WASM must be optimized with
/// `wasm-opt -Oz` to fit within the sandbox's HTTP body limit.
///
/// ```sh
/// cargo build -p mpc-contract --target=wasm32-unknown-unknown --profile=release-contract --locked
/// wasm-opt -Oz target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm \
///   -o target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm
/// ```
fn load_contract_wasm() -> Vec<u8> {
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
             cargo build -p mpc-contract --target=wasm32-unknown-unknown --profile=release-contract --locked\n  \
             wasm-opt -Oz <path> -o <path>",
            wasm_path.display()
        )
    })
}

fn generate_ecdsa_payload() -> serde_json::Value {
    let bytes: [u8; 32] = rand::random();
    json!({ "Ecdsa": hex::encode(bytes) })
}

fn generate_eddsa_payload() -> serde_json::Value {
    let bytes: [u8; 32] = rand::random();
    json!({ "Eddsa": hex::encode(bytes) })
}

#[tokio::test]
async fn test_request_lifecycle() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,e2e_tests=debug".parse().unwrap()),
        )
        .try_init()
        .ok();

    // Given: a running MPC cluster with presignatures ready.
    let contract_wasm = load_contract_wasm();
    let config = MpcClusterConfig::default_for_test(1, contract_wasm);
    let cluster = MpcCluster::start(config)
        .await
        .expect("failed to start cluster");

    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get contract state");
    let running = match &state {
        ProtocolContractState::Running(r) => r,
        other => panic!("expected Running state, got: {other:?}"),
    };

    let sign_domains: Vec<_> = running
        .domains
        .domains
        .iter()
        .filter(|d| d.purpose == Some(DomainPurpose::Sign))
        .collect();
    assert!(!sign_domains.is_empty(), "no Sign domains found");

    cluster
        .wait_for_metric_all_nodes(
            "mpc_owned_num_presignatures_available",
            |v| {
                let expected = i64::try_from(e2e_tests::DEFAULT_PRESIGNATURES_TO_BUFFER)
                    .expect("presignatures_to_buffer exceeds i64::MAX");
                v >= expected
            },
            Duration::from_secs(120),
        )
        .await
        .expect("nodes did not generate presignatures in time");

    // When: we send a sign request for each Sign domain.
    // Then: each returns a valid signature matching the requested scheme.
    for domain in &sign_domains {
        let payload = match domain.scheme {
            SignatureScheme::Secp256k1 => generate_ecdsa_payload(),
            SignatureScheme::Ed25519 => generate_eddsa_payload(),
            _ => continue,
        };

        tracing::info!(domain_id = ?domain.id, scheme = ?domain.scheme, "sending sign request");
        let outcome = cluster
            .send_sign_request(domain.id, payload)
            .await
            .expect("sign request transaction failed");

        assert!(
            outcome.is_success(),
            "sign request for domain {:?} failed: {:?}",
            domain.id,
            outcome.failure_message()
        );

        let signature: SignatureResponse = outcome
            .json()
            .expect("failed to deserialize SignatureResponse from transaction result");

        match (&domain.scheme, &signature) {
            (SignatureScheme::Secp256k1, SignatureResponse::Secp256k1(_)) => {}
            (SignatureScheme::Ed25519, SignatureResponse::Ed25519 { .. }) => {}
            _ => panic!(
                "signature scheme mismatch: requested {:?}, got {:?}",
                domain.scheme, signature
            ),
        }
        tracing::info!(domain_id = ?domain.id, "sign request returned valid signature");
    }
}
