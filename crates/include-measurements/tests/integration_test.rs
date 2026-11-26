#![allow(non_snake_case)]

use attestation_types::{ExpectedMeasurements, Measurements};
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

    let expected_mrtd = hex::decode("2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70").unwrap();
    let mut expected_mrtd_array = [0u8; 48];
    expected_mrtd_array.copy_from_slice(&expected_mrtd);
    assert_eq!(measurements.rtmrs.mrtd, expected_mrtd_array);
}
