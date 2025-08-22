#![no_std]

extern crate alloc;

pub mod app_compose;
pub mod attestation;
pub mod collateral;
pub mod measurements;
pub mod quote;
pub mod report_data;

#[cfg(feature = "test-utils")]
pub mod test_utils {
    extern crate std;

    use crate::{
        attestation::{Attestation, DstackAttestation, LocalAttestation},
        collateral::Collateral,
        measurements::{ExpectedMeasurements, Measurements},
        quote::QuoteBytes,
        report_data::ReportDataVersion,
    };
    use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;
    use near_sdk::PublicKey;
    use serde_json::Value;

    pub const TEST_TCB_INFO_STRING: &str = include_str!("../tests/assets/tcb_info.json");
    pub const TEST_APP_COMPOSE_STRING: &str = include_str!("../tests/assets/app_compose.json");
    pub const TEST_APP_COMPOSE_WITH_SERVICES_STRING: &str =
        include_str!("../tests/assets/app_compose_with_services.json");

    pub const TEST_LAUNCHER_IMAGE_COMPOSE_STRING: &str =
        include_str!("../tests/assets/launcher_image_compose.yaml");

    /// App compose field corresponds to the `DEFAULT_IMAGE_DIGEST` field in
    /// attestation/tests/assets/launcher_image_compose.yaml
    pub const TEST_MPC_IMAGE_DIGEST_HEX: &str =
        include_str!("../tests/assets/mpc_image_digest.txt");
    /// sha256sum attestation/tests/assets/launcher_image_compose.yaml
    pub const TEST_LAUNCHER_COMPOSE_DIGEST_HEX: &str =
        "9f9f570c2b84cb56d537abb6a4ab4b3cc93a6a84da4e2c21bddba8963726fdaa";

    pub fn collateral() -> Value {
        let quote_collateral_json_string = include_str!("../tests/assets/collateral.json");
        quote_collateral_json_string
            .parse()
            .expect("Quote collateral file is a valid json.")
    }

    pub fn quote() -> QuoteBytes {
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

    pub fn mock_dstack_attestation() -> Attestation {
        let quote = quote();
        let collateral = Collateral::try_from_json(collateral()).unwrap();

        let tcb_info: DstackTcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();

        let expected_measurements = ExpectedMeasurements {
            rtmrs: Measurements {
                rtmr0: [
                    0x37, 0x44, 0xb1, 0x54, 0x06, 0x95, 0x00, 0xa4, 0x66, 0xf5, 0x14, 0x25, 0x3b,
                    0x49, 0x85, 0x82, 0x99, 0xb2, 0xe1, 0xbd, 0xc4, 0x4e, 0x3d, 0x55, 0x73, 0x37,
                    0xd8, 0x1e, 0x82, 0x8b, 0xed, 0xf6, 0xa0, 0x41, 0x0f, 0x27, 0xd3, 0xa1, 0x8c,
                    0x93, 0x2e, 0x5e, 0x49, 0xe1, 0xc4, 0x21, 0x57, 0x37,
                ],
                rtmr1: [
                    0x4b, 0x66, 0xe8, 0x88, 0xc8, 0xdf, 0xa7, 0xa5, 0x04, 0xfc, 0x7c, 0xa0, 0x60,
                    0xab, 0x9e, 0x2d, 0x05, 0x12, 0x33, 0xf1, 0x15, 0xd7, 0x13, 0x04, 0x08, 0x55,
                    0x70, 0xc7, 0xac, 0x71, 0xf5, 0xa1, 0x90, 0xa3, 0xe2, 0x37, 0xd1, 0x5f, 0x09,
                    0x65, 0x96, 0x7a, 0x78, 0x53, 0x9b, 0xa0, 0xd7, 0x87,
                ],
                rtmr2: [
                    0x5a, 0x41, 0xc9, 0xf7, 0x1c, 0xe5, 0x65, 0x5b, 0x6b, 0xa6, 0x05, 0xfe, 0x0d,
                    0x00, 0xa0, 0xa0, 0x5a, 0xdd, 0x74, 0x71, 0xac, 0xaa, 0xa6, 0xaa, 0x15, 0x5b,
                    0xce, 0x1e, 0x04, 0xb8, 0x20, 0x4f, 0x0f, 0xff, 0xae, 0xc2, 0xe6, 0xc9, 0x5f,
                    0xfc, 0x14, 0x42, 0xb3, 0x7e, 0x14, 0x11, 0x27, 0xd9,
                ],
                mrtd: [
                    0xc6, 0x85, 0x18, 0xa0, 0xeb, 0xb4, 0x21, 0x36, 0xc1, 0x2b, 0x22, 0x75, 0x16,
                    0x4f, 0x8c, 0x72, 0xf2, 0x5f, 0xa9, 0xa3, 0x43, 0x92, 0x22, 0x86, 0x87, 0xed,
                    0x6e, 0x9c, 0xae, 0xb9, 0xc0, 0xf1, 0xdb, 0xd8, 0x95, 0xe9, 0xcf, 0x47, 0x51,
                    0x21, 0xc0, 0x29, 0xdc, 0x47, 0xe7, 0x0e, 0x91, 0xfd,
                ],
            },
            local_sgx_event_digest: [
                0x74, 0xca, 0x93, 0x9b, 0x8c, 0x3c, 0x74, 0xaa, 0xb3, 0xc3, 0x09, 0x66, 0xa7, 0x88,
                0xf7, 0x74, 0x39, 0x51, 0xd5, 0x4a, 0x93, 0x6a, 0x71, 0x1d, 0xd0, 0x14, 0x22, 0xf0,
                0x03, 0xff, 0x9d, 0xf6, 0x66, 0x6f, 0x3c, 0xc5, 0x49, 0x75, 0xd2, 0xe4, 0xf3, 0x5c,
                0x82, 0x98, 0x65, 0x58, 0x3f, 0x0f,
            ],
            report_data_version: ReportDataVersion::V1,
        };
        Attestation::Dstack(DstackAttestation::new(
            quote,
            collateral,
            tcb_info,
            expected_measurements,
        ))
    }
}
