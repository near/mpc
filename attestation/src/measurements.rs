use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
use alloc::string::ToString;

use crate::report_data::ReportDataVersion;
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;

/// TCB info JSON file containing measurement values.
const TCB_INFO_STRING: &str = include_str!("../assets/tcb_info.json");

// The `EXPECTED_LOCAL_SGX_EVENT_DIGEST` is the expected SHA-384 digest for the `local-sgx` event,
// not the event payload.
//
// Digest format:
//   digest = SHA384( event_type + ":" + "key-provider" + ":"+payload) )
//
// Payload format: sha256 {"name":"local-sgx", "id": "<mr_enclave of the provider>"}

// This value must match the digest below for the test to pass.
const EXPECTED_LOCAL_SGX_EVENT_DIGEST: [u8; 48] = [
    0x74, 0xca, 0x93, 0x9b, 0x8c, 0x3c, 0x74, 0xaa, 0xb3, 0xc3, 0x09, 0x66, 0xa7, 0x88, 0xf7, 0x74,
    0x39, 0x51, 0xd5, 0x4a, 0x93, 0x6a, 0x71, 0x1d, 0xd0, 0x14, 0x22, 0xf0, 0x03, 0xff, 0x9d, 0xf6,
    0x66, 0x6f, 0x3c, 0xc5, 0x49, 0x75, 0xd2, 0xe4, 0xf3, 0x5c, 0x82, 0x98, 0x65, 0x58, 0x3f, 0x0f,
];

const EXPECTED_REPORT_DATA_VERSION: ReportDataVersion = ReportDataVersion::V1;

/// Required measurements for TEE attestation verification (a.k.a. RTMRs checks). These values
/// define the trusted baseline that TEE environments must match during verification. They
/// should be updated when the underlying TEE environment changes.
///
/// To learn more about the RTMRs, see:
/// - https://docs.phala.network/phala-cloud/tees-attestation-and-zero-trust-security/attestation#runtime-measurement-fields
/// - https://arxiv.org/pdf/2303.15540 (Section 9.1)
#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct Measurements {
    /// MRTD (Measurement of Root of Trust for Data) - identifies the virtual firmware.
    #[serde_as(as = "Bytes")]
    pub mrtd: [u8; 48],
    /// RTMR0 (Runtime Measurement Register 0) - typically measures the bootloader, virtual
    /// firmware data, and configuration.
    #[serde_as(as = "Bytes")]
    pub rtmr0: [u8; 48],
    /// RTMR1 (Runtime Measurement Register 1) - typically measures the OS kernel, boot parameters,
    /// and initrd (initial ramdisk).
    #[serde_as(as = "Bytes")]
    pub rtmr1: [u8; 48],
    /// RTMR2 (Runtime Measurement Register 2) - typically measures the OS application.
    #[serde_as(as = "Bytes")]
    pub rtmr2: [u8; 48],
}

#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct ExpectedMeasurements {
    /// Expected RTMRs (Runtime Measurement Registers).
    pub rtmrs: Measurements,
    /// Expected digest for the local SGX event.
    #[serde_as(as = "Bytes")]
    pub local_sgx_event_digest: [u8; 48],
    /// Expected version of the report data.
    pub report_data_version: ReportDataVersion,
}

/// Default implementation that provides the expected measurements for TEE attestation verification.
/// This implementation reads measurement values (RTMR0, RTMR1, RTMR2, MRTD) from the embedded
/// TCB (Trusted Computing Base) info JSON file at compile time, ensuring consistent measurements
/// across both production and test environments.
///
/// The TCB info contains hex-encoded measurement values that are decoded and converted to the
/// required 48-byte arrays for each measurement register. This provides a single source of truth
/// for all expected measurements.
///
/// TODO(#737): Define a process for updating these static RTMRs going forward, since they are already outdated.
///
/// $ git rev-parse HEAD
/// fbdf2e76fb6bd9142277fdd84809de87d86548ef
///
/// See also: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image
impl Default for ExpectedMeasurements {
    fn default() -> Self {
        // Parse embedded tcb_info.json file and extract RTMR values dynamically
        let tcb_info: DstackTcbInfo =
            serde_json::from_str(TCB_INFO_STRING).expect("Failed to parse embedded tcb_info.json");

        // Extract RTMR values from the TCB info (they're in hex format)
        let rtmr0 = hex::decode(&tcb_info.rtmr0).expect("Failed to decode rtmr0 from tcb_info");
        let rtmr1 = hex::decode(&tcb_info.rtmr1).expect("Failed to decode rtmr1 from tcb_info");
        let rtmr2 = hex::decode(&tcb_info.rtmr2).expect("Failed to decode rtmr2 from tcb_info");
        let mrtd = hex::decode(&tcb_info.mrtd).expect("Failed to decode mrtd from tcb_info");

        // Convert to fixed-size arrays
        let mut rtmr0_arr = [0u8; 48];
        let mut rtmr1_arr = [0u8; 48];
        let mut rtmr2_arr = [0u8; 48];
        let mut mrtd_arr = [0u8; 48];

        rtmr0_arr.copy_from_slice(&rtmr0);
        rtmr1_arr.copy_from_slice(&rtmr1);
        rtmr2_arr.copy_from_slice(&rtmr2);
        mrtd_arr.copy_from_slice(&mrtd);

        Self {
            rtmrs: Measurements {
                mrtd: mrtd_arr,
                rtmr0: rtmr0_arr,
                rtmr1: rtmr1_arr,
                rtmr2: rtmr2_arr,
            },
            local_sgx_event_digest: EXPECTED_LOCAL_SGX_EVENT_DIGEST,
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
