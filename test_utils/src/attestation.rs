use attestation::{
    attestation::{Attestation, DstackAttestation, LocalAttestation},
    collateral::Collateral,
    measurements::ExpectedMeasurements,
    quote::QuoteBytes,
};
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;
use near_sdk::PublicKey;
use serde_json::Value;

pub const TEST_TCB_INFO_STRING: &str = include_str!("../assets/tcb_info.json");
pub const TEST_APP_COMPOSE_STRING: &str = include_str!("../assets/app_compose.json");
pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
    include_str!("../assets/app_compose_with_services.json");

pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str =
    include_str!("../assets/launcher_image_compose.yaml");

/// App compose field corresponds to the `DEFAULT_IMAGE_DIGEST` field in
/// test_utils/assets/launcher_image_compose.yaml
pub const TEST_MPC_IMAGE_DIGEST_HEX: &str = include_str!("../assets/mpc_image_digest.txt");
/// sha256sum test_utils/assets/launcher_image_compose.yaml
pub const TEST_LAUNCHER_COMPOSE_DIGEST_HEX: &str =
    "9f9f570c2b84cb56d537abb6a4ab4b3cc93a6a84da4e2c21bddba8963726fdaa";

pub fn collateral() -> Value {
    let quote_collateral_json_string = include_str!("../assets/collateral.json");
    quote_collateral_json_string
        .parse()
        .expect("Quote collateral file is a valid json.")
}

pub fn quote() -> QuoteBytes {
    let quote_collateral_json_string = include_str!("../assets/quote.json");
    serde_json::from_str(quote_collateral_json_string)
        .expect("Quote collateral file is a valid json.")
}

pub fn mock_local_attestation(quote_verification_result: bool) -> Attestation {
    Attestation::Local(LocalAttestation::new(quote_verification_result))
}

pub fn p2p_tls_key() -> PublicKey {
    let key_file = include_str!("../assets/near_p2p_public_key.pub");
    key_file.parse().expect("File contains a valid public key")
}

pub fn mock_dstack_attestation() -> Attestation {
    let quote = quote();
    let collateral = Collateral::try_from_json(collateral()).unwrap();

    let tcb_info: DstackTcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    Attestation::Dstack(DstackAttestation::new(quote, collateral, tcb_info))
}

/// Get expected measurements compatible with the test data from tcb_info.json.
/// This creates measurements that match the actual values in the test quote and TCB info.
/// Use this for standalone attestation tests that verify against real test data.
pub fn test_expected_measurements() -> ExpectedMeasurements {
    let tcb_info: DstackTcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

    // Extract RTMR values from the TCB info (they're in hex format)
    let rtmr0 = hex::decode(&tcb_info.rtmr0).unwrap();
    let rtmr1 = hex::decode(&tcb_info.rtmr1).unwrap();
    let rtmr2 = hex::decode(&tcb_info.rtmr2).unwrap();
    let mrtd = hex::decode(&tcb_info.mrtd).unwrap();

    // Convert to fixed-size arrays
    let mut rtmr0_arr = [0u8; 48];
    let mut rtmr1_arr = [0u8; 48];
    let mut rtmr2_arr = [0u8; 48];
    let mut mrtd_arr = [0u8; 48];

    rtmr0_arr.copy_from_slice(&rtmr0);
    rtmr1_arr.copy_from_slice(&rtmr1);
    rtmr2_arr.copy_from_slice(&rtmr2);
    mrtd_arr.copy_from_slice(&mrtd);

    ExpectedMeasurements {
        rtmrs: attestation::measurements::Measurements {
            mrtd: mrtd_arr,
            rtmr0: rtmr0_arr,
            rtmr1: rtmr1_arr,
            rtmr2: rtmr2_arr,
        },
        // Use default values for other fields
        local_sgx_event_digest: ExpectedMeasurements::default().local_sgx_event_digest,
        report_data_version: ExpectedMeasurements::default().report_data_version,
    }
}
