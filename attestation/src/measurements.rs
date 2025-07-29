/// Required measurements for TEE attestation verification (a.k.a. RTMRs checks). These values
/// define the trusted baseline that TEE environments must match during verification. They
/// should be updated when the underlying TEE environment changes.
///
/// To learn more about the RTMRs, see:
/// - https://docs.phala.network/phala-cloud/tees-attestation-and-zero-trust-security/attestation#runtime-measurement-fields
/// - https://arxiv.org/pdf/2303.15540 (Section 9.1)
// Default measurement values from git commit fbdf2e76fb6bd9142277fdd84809de87d86548ef
// See: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image
use crate::report_data::ReportDataVersion;

const EXPECTED_MRTD: [u8; 48] = [
    0xc6, 0x85, 0x18, 0xa0, 0xeb, 0xb4, 0x21, 0x36, 0xc1, 0x2b, 0x22, 0x75, 0x16, 0x4f, 0x8c, 0x72,
    0xf2, 0x5f, 0xa9, 0xa3, 0x43, 0x92, 0x22, 0x86, 0x87, 0xed, 0x6e, 0x9c, 0xae, 0xb9, 0xc0, 0xf1,
    0xdb, 0xd8, 0x95, 0xe9, 0xcf, 0x47, 0x51, 0x21, 0xc0, 0x29, 0xdc, 0x47, 0xe7, 0x0e, 0x91, 0xfd,
];

const EXPECTED_RTMR0: [u8; 48] = [
    0x7a, 0xe1, 0xc6, 0xbc, 0x16, 0x53, 0xc4, 0xcf, 0x03, 0x7b, 0x0e, 0xe6, 0x02, 0x94, 0x57, 0xee,
    0x67, 0xc4, 0x75, 0x28, 0x5b, 0xcf, 0x47, 0x2a, 0x92, 0xf5, 0x18, 0x43, 0x14, 0x8e, 0x47, 0x7f,
    0x31, 0x26, 0x18, 0x4d, 0xd6, 0x92, 0x82, 0x27, 0x9d, 0x27, 0x8a, 0x74, 0x66, 0xb6, 0x6c, 0xae,
];

const EXPECTED_RTMR1: [u8; 48] = [
    0xa7, 0x07, 0xa3, 0x36, 0x70, 0x0c, 0x7d, 0xf3, 0x08, 0x52, 0x1f, 0x70, 0x44, 0xd0, 0xcd, 0x46,
    0xe1, 0x62, 0xb7, 0xea, 0xeb, 0x6c, 0x1a, 0x91, 0xa0, 0x8e, 0x32, 0xe3, 0xd8, 0xd4, 0xb0, 0xad,
    0x01, 0xfe, 0x8f, 0xbc, 0x2b, 0x91, 0x30, 0x20, 0x26, 0x2a, 0x45, 0x5f, 0xa6, 0xb1, 0xa5, 0xc4,
];

const EXPECTED_RTMR2: [u8; 48] = [
    0x2e, 0x36, 0xd0, 0xb6, 0x1a, 0x3a, 0x20, 0xc2, 0xdf, 0xbf, 0xf7, 0x0c, 0x96, 0x00, 0x5f, 0xf3,
    0xe1, 0xc7, 0x81, 0x3b, 0x4a, 0xba, 0xb4, 0x52, 0x57, 0x03, 0x30, 0xdd, 0xeb, 0xab, 0xf9, 0x39,
    0x39, 0x30, 0x99, 0x23, 0x4a, 0xbc, 0x03, 0x09, 0xf0, 0x39, 0x36, 0xed, 0xeb, 0xf7, 0x4b, 0x1f,
];

const EXPECTED_LOCAL_SGX_HASH: [u8; 32] = [
    0x1b, 0x7a, 0x49, 0x37, 0x84, 0x03, 0x24, 0x9b, 0x69, 0x86, 0xa9, 0x07, 0x84, 0x4c, 0xab, 0x09,
    0x21, 0xec, 0xa3, 0x2d, 0xd4, 0x7e, 0x65, 0x7f, 0x3c, 0x10, 0x31, 0x1c, 0xca, 0xec, 0xcf, 0x8b,
];

const EXPECTED_REPORT_DATA_VERSION: ReportDataVersion = ReportDataVersion::V1;

#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    /// MRTD (Measurement of Root of Trust for Data) - identifies the virtual firmware.
    pub mrtd: [u8; 48],
    /// RTMR0 (Runtime Measurement Register 0) - typically measures the bootloader, virtual
    /// firmware data, and configuration.
    pub rtmr0: [u8; 48],
    /// RTMR1 (Runtime Measurement Register 1) - typically measures the OS kernel, boot parameters,
    /// and initrd
    pub rtmr1: [u8; 48],
    /// RTMR2 (Runtime Measurement Register 2) - typically measures the OS application.
    pub rtmr2: [u8; 48],
}

#[derive(Debug, Clone, Copy)]
pub struct ExpectedMeasurements {
    /// Expected RTMRs (Runtime Measurement Registers).
    pub rtmrs: Measurements,
    /// Expected hash for the local SGX component.
    pub local_sgx_hash: [u8; 32],
    /// Expected version of the report data.
    pub report_data_version: ReportDataVersion,
}

impl Default for ExpectedMeasurements {
    fn default() -> Self {
        // TODO(#737): Define a process for updating these static RTMRs going forward, since they
        // are already outdated.
        //
        // $ git rev-parse HEAD
        // fbdf2e76fb6bd9142277fdd84809de87d86548ef
        //
        // See also: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image
        Self {
            rtmrs: Measurements {
                mrtd: EXPECTED_MRTD,
                rtmr0: EXPECTED_RTMR0,
                rtmr1: EXPECTED_RTMR1,
                rtmr2: EXPECTED_RTMR2,
            },
            local_sgx_hash: EXPECTED_LOCAL_SGX_HASH,
            report_data_version: EXPECTED_REPORT_DATA_VERSION,
        }
    }
}

#[derive(Debug)]
pub enum MeasurementsError {
    NoTd10Report,
}

impl TryFrom<dcap_qvl::verify::VerifiedReport> for Measurements {
    type Error = MeasurementsError;

    fn try_from(verified_report: dcap_qvl::verify::VerifiedReport) -> Result<Self, Self::Error> {
        let td10 = verified_report
            .report
            .as_td10()
            .ok_or(MeasurementsError::NoTd10Report)?;
        Ok(Self {
            rtmr0: td10.rt_mr0,
            rtmr1: td10.rt_mr1,
            rtmr2: td10.rt_mr2,
            mrtd: td10.mr_td,
        })
    }
}
