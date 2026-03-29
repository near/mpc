use std::path::Path;
use std::time::Duration;

use e2e_tests::{MpcCluster, MpcClusterConfig};
use near_mpc_contract_interface::types::{
    DomainPurpose, ProtocolContractState, SignatureResponse, SignatureScheme,
};
use serde_json::json;

/// Load the pre-built MPC contract WASM.
///
/// Expects the WASM to be pre-optimized with `wasm-opt -Oz` so it fits within
/// the NEAR sandbox's HTTP body limit. Build it with:
/// ```sh
/// cargo build -p mpc-contract --target=wasm32-unknown-unknown --profile=release-contract --locked
/// wasm-opt -Oz target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm \
///   -o target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm
/// ```
fn load_contract_wasm() -> Vec<u8> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wasm_path =
        manifest_dir.join("../../target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm");

    std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read contract WASM at {}: {e}\n\
             Build it first:\n  \
             cargo build -p mpc-contract --target=wasm32-unknown-unknown --profile=release-contract --locked\n  \
             wasm-opt -Oz {p} -o {p}",
            wasm_path.display(),
            p = wasm_path.display()
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

    let contract_wasm = load_contract_wasm();
    let config = MpcClusterConfig::default_for_test(1, contract_wasm);
    let cluster = MpcCluster::start(config)
        .await
        .expect("failed to start cluster");

    // Verify contract is in Running state with expected domains.
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

    // Wait for nodes to generate presignatures before sending requests.
    cluster
        .wait_for_metric_all_nodes(
            "mpc_owned_num_presignatures_available",
            1,
            Duration::from_secs(120),
        )
        .await
        .expect("nodes did not generate presignatures in time");

    // Send a sign request for each Sign domain.
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
