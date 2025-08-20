use attestation::attestation::{Attestation, LocalAttestation};
use near_crypto::PublicKey;
use serde_json::Value;

pub const TEST_TCB_INFO_STRING: &str = include_str!("../tests/assets/tcb_info.json");
pub const TEST_APP_COMPOSE_STRING: &str = include_str!("../tests/assets/app_compose.json");
pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
    include_str!("../tests/assets/app_compose_with_services.json");

pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str =
    include_str!("../tests/assets/launcher_image_compose.yaml");

/// App compose field corresponds to the `DEFAULT_IMAGE_DIGEST` field in
/// attestation/tests/assets/launcher_image_compose.yaml
///
/// DEFAULT_IMAGE_DIGEST=sha256:8d46a34ac16f7bc5f3c6bfe824ef741306fa00df1b098811885b0ecf1408e013
pub const TEST_MPC_IMAGE_DIGEST_HEX: &str = include_str!("../tests/assets/mpc_image_digest.txt");
/// sha256sum attestation/tests/assets/launcher_image_compose.yaml
pub const TEST_LAUNCHER_COMPOSE_DIGEST_HEX: &str =
    "9f9f570c2b84cb56d537abb6a4ab4b3cc93a6a84da4e2c21bddba8963726fdaa";

pub fn collateral() -> Value {
    let quote_collateral_json_string = include_str!("../tests/assets/collateral.json");
    quote_collateral_json_string
        .parse()
        .expect("Quote collateral file is a valid json.")
}

pub fn quote() -> Vec<u8> {
    let quote_collateral_json_string = include_str!("../tests/assets/quote.json");
    serde_json::from_str(quote_collateral_json_string)
        .expect("Quote collateral file is a valid json.")
}

pub fn mock_local_attestation(quote_verification_result: bool) -> Attestation {
    Attestation::Local(LocalAttestation::new(quote_verification_result))
}

pub fn p2p_tls_key() -> PublicKey {
    let key_file = include_str!("../tests/assets/near_p2p_public_key.pub");
    key_file.parse().expect("File contains a valid public key")
}
