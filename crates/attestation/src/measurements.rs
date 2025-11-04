use alloc::string::String;
use borsh::{BorshDeserialize, BorshSerialize};
use core::cell::LazyCell;
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

use crate::report_data::ReportDataVersion;
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;

/// TCB info JSON file containing measurement values.
const TCB_INFO_STRING: &str = include_str!("../assets/tcb_info.json");

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
pub struct ExpectedMeasurements {
    /// Expected RTMRs (Runtime Measurement Registers).
    pub rtmrs: Measurements,
    /// Expected digest for the local SGX event.
    #[serde_as(as = "Bytes")]
    pub local_sgx_event_digest: [u8; 48],
    /// Expected version of the report data.
    pub report_data_version: ReportDataVersion,
}

impl ExpectedMeasurements {
    /// Loads expected measurements from the embedded TCB info file for TEE attestation verification.
    /// This implementation uses a cached computation to avoid runtime JSON parsing and hex decoding,
    /// improving performance especially in smart contract environments where every cycle counts.
    ///
    /// The TCB info contains hex-encoded measurement values that are decoded once and cached for
    /// all subsequent calls, ensuring consistent measurements across both production and test environments.
    ///
    /// TODO(#737): Define a process for updating these static RTMRs going forward, since they are already outdated.
    ///
    /// $ git rev-parse HEAD
    /// fbdf2e76fb6bd9142277fdd84809de87d86548ef
    ///
    /// See also: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image
    pub fn from_embedded_tcb_info() -> Result<Self, MeasurementsError> {
        let cache = LazyCell::new(|| -> Result<ExpectedMeasurements, MeasurementsError> {
            // Parse embedded tcb_info.json file and extract RTMR values dynamically
            let tcb_info: DstackTcbInfo = serde_json::from_str(TCB_INFO_STRING)
                .map_err(|_| MeasurementsError::InvalidTcbInfo)?;

            // Helper function to decode hex RTMR values
            let decode_rtmr = |name: &str,
                               hex_value: &str|
             -> Result<[u8; 48], MeasurementsError> {
                let decoded = hex::decode(hex_value).map_err(|_| {
                    MeasurementsError::InvalidHexValue(String::from(name), String::from(hex_value))
                })?;
                let decoded_len = decoded.len();
                decoded
                    .try_into()
                    .map_err(|_| MeasurementsError::InvalidLength(String::from(name), decoded_len))
            };

            let rtmrs = Measurements {
                rtmr0: decode_rtmr("rtmr0", &tcb_info.rtmr0)?,
                rtmr1: decode_rtmr("rtmr1", &tcb_info.rtmr1)?,
                rtmr2: decode_rtmr("rtmr2", &tcb_info.rtmr2)?,
                mrtd: decode_rtmr("mrtd", &tcb_info.mrtd)?,
            };

            Ok(ExpectedMeasurements {
                rtmrs,
                local_sgx_event_digest: EXPECTED_LOCAL_SGX_EVENT_DIGEST,
                report_data_version: EXPECTED_REPORT_DATA_VERSION,
            })
        });

        (*cache).clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeasurementsError {
    #[error("no TD10 report")]
    NoTd10Report,
    #[error("invalid TCB info")]
    InvalidTcbInfo,
    #[error("invalid hex value for {0}: {1}")]
    InvalidHexValue(String, String),
    #[error("invalid length for {0}: {1}")]
    InvalidLength(String, usize),
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
