use attestation::attestation::{Attestation, LocalAttestation};
use serde_json::Value;

pub const TEST_TCB_INFO_STRING: &str = include_str!("../tests/assets/tcb_info.json");
pub const TEST_MPC_IMAGE_DIGEST_HEX: &str =
    "a87f7eb6882446dd714e6d47d9d1b9331cb333f36d3905f172c68adbd06e461f";
pub const TEST_LAUNCHER_COMPOSE_NORMALIZED_DIGEST_HEX: &str =
    "12997af6d2ae488b8c09d8a46488a6d48742374675fe964051eca91299182b56";

pub const TEST_APP_COMPOSE_STRING: &str = include_str!("../tests/assets/app_compose.json");
pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
    include_str!("../tests/assets/app_compose_with_services.json");

pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str =
    include_str!("../tests/assets/launcher_image_compose.yaml");
pub const TEST_LAUNCHER_IMAGE_COMPOSE_NORMALIZED_STRING: &str =
    include_str!("../tests/assets/launcher_image_compose_normalized.yaml");

pub fn mock_local_attestation(quote_verification_result: bool) -> Attestation {
    Attestation::Local(LocalAttestation::new(quote_verification_result))
}

pub fn create_test_collateral_json() -> Value {
    let quote_collateral_json_string = include_str!("../tests/assets/quote_collateral.json");
    quote_collateral_json_string
        .parse()
        .expect("Quote collateral file is a valid json.")
}
