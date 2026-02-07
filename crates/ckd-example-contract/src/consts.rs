use attestation::measurements::ExpectedMeasurements;
use attestation::measurements::Measurements;
use include_measurements::include_measurements;

pub(crate) const EXPECTED_REPORT_DATA: [u8; 64] = [0u8; 64];

pub(crate) const ACCEPTED_MEASUREMENT: ExpectedMeasurements =
    include_measurements!("assets/tcb_info.json");
