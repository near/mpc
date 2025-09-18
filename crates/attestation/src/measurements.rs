use crate::report_data::ReportDataVersion;

pub const EXPECTED_MEASUREMENTS: ExpectedMeasurements = ExpectedMeasurements {
    rtmrs: EXPECTED_RTMR_MEASUREMENTS,
    local_sgx_event_digest: EXPECTED_LOCAL_SGX_EVENT_DIGEST,
    report_data_version: EXPECTED_REPORT_DATA_VERSION,
};

/// TCB info JSON file containing measurement values.
/// The expected SHA-384 digest for the `local-sgx` event, not the event payload.
///
/// Digest format:
///   digest = SHA384( event_type + ":" + "key-provider" + ":"+payload) )
///
/// Payload format: sha256 {"name":"local-sgx", "id": "<mr_enclave of the provider>"}
const EXPECTED_LOCAL_SGX_EVENT_DIGEST: [u8; 48] = [
    0x74, 0xca, 0x93, 0x9b, 0x8c, 0x3c, 0x74, 0xaa, 0xb3, 0xc3, 0x09, 0x66, 0xa7, 0x88, 0xf7, 0x74,
    0x39, 0x51, 0xd5, 0x4a, 0x93, 0x6a, 0x71, 0x1d, 0xd0, 0x14, 0x22, 0xf0, 0x03, 0xff, 0x9d, 0xf6,
    0x66, 0x6f, 0x3c, 0xc5, 0x49, 0x75, 0xd2, 0xe4, 0xf3, 0x5c, 0x82, 0x98, 0x65, 0x58, 0x3f, 0x0f,
];

const EXPECTED_RTMR_MEASUREMENTS: Measurements = Measurements {
    mrtd: [
        198, 133, 24, 160, 235, 180, 33, 54, 193, 43, 34, 117, 22, 79, 140, 114, 242, 95, 169, 163,
        67, 146, 34, 134, 135, 237, 110, 156, 174, 185, 192, 241, 219, 216, 149, 233, 207, 71, 81,
        33, 192, 41, 220, 71, 231, 14, 145, 253,
    ],
    rtmr0: [
        55, 68, 177, 84, 6, 149, 0, 164, 102, 245, 20, 37, 59, 73, 133, 130, 153, 178, 225, 189,
        196, 78, 61, 85, 115, 55, 216, 30, 130, 139, 237, 246, 160, 65, 15, 39, 211, 161, 140, 147,
        46, 94, 73, 225, 196, 33, 87, 55,
    ],
    rtmr1: [
        75, 102, 232, 136, 200, 223, 167, 165, 4, 252, 124, 160, 96, 171, 158, 45, 5, 18, 51, 241,
        21, 215, 19, 4, 8, 85, 112, 199, 172, 113, 245, 161, 144, 163, 226, 55, 209, 95, 9, 101,
        150, 122, 120, 83, 155, 160, 215, 135,
    ],
    rtmr2: [
        90, 65, 201, 247, 28, 229, 101, 91, 107, 166, 5, 254, 13, 0, 160, 160, 90, 221, 116, 113,
        172, 170, 166, 170, 21, 91, 206, 30, 4, 184, 32, 79, 15, 255, 174, 194, 230, 201, 95, 252,
        20, 66, 179, 126, 20, 17, 39, 217,
    ],
};

const EXPECTED_REPORT_DATA_VERSION: ReportDataVersion = ReportDataVersion::V1;

/// Required measurements for TEE attestation verification (a.k.a. RTMRs checks). These values
/// define the trusted baseline that TEE environments must match during verification. They
/// should be updated when the underlying TEE environment changes.
///
/// To learn more about the RTMRs, see:
/// - https://docs.phala.network/phala-cloud/tees-attestation-and-zero-trust-security/attestation#runtime-measurement-fields
/// - https://arxiv.org/pdf/2303.15540 (Section 9.1)
#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    /// MRTD (Measurement of Root of Trust for Data) - identifies the virtual firmware.
    pub mrtd: [u8; 48],
    /// RTMR0 (Runtime Measurement Register 0) - typically measures the bootloader, virtual
    /// firmware data, and configuration.
    pub rtmr0: [u8; 48],
    /// RTMR1 (Runtime Measurement Register 1) - typically measures the OS kernel, boot parameters,
    /// and initrd (initial ramdisk).
    pub rtmr1: [u8; 48],
    /// RTMR2 (Runtime Measurement Register 2) - typically measures the OS application.
    pub rtmr2: [u8; 48],
}

#[derive(Debug, Clone, Copy)]
pub struct ExpectedMeasurements {
    /// Expected RTMRs (Runtime Measurement Registers).
    pub rtmrs: Measurements,
    /// Expected digest for the local SGX event.
    pub local_sgx_event_digest: [u8; 48],
    /// Expected version of the report data.
    pub report_data_version: ReportDataVersion,
}
