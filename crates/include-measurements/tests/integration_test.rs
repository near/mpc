#![allow(non_snake_case)]

use attestation::measurements::{ExpectedMeasurements, Measurements};
use include_measurements::include_measurements;

#[test]
fn include_measurements__should_generate_expected_measurements() {
    let measurements: ExpectedMeasurements =
        include_measurements!("../mpc-attestation/assets/tcb_info.json");

    assert_ne!(measurements.rtmrs.mrtd, [0u8; 48]);
    assert_ne!(measurements.rtmrs.rtmr0, [0u8; 48]);
    assert_ne!(measurements.rtmrs.rtmr1, [0u8; 48]);
    assert_ne!(measurements.rtmrs.rtmr2, [0u8; 48]);
    assert_ne!(measurements.key_provider_event_digest, [0u8; 48]);

    let expected_mrtd = hex::decode("f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077").unwrap();
    let mut expected_mrtd_array = [0u8; 48];
    expected_mrtd_array.copy_from_slice(&expected_mrtd);
    assert_eq!(measurements.rtmrs.mrtd, expected_mrtd_array);
}
