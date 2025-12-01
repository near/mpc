use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

use dstack_sdk_types::dstack::{EventLog, TcbInfo as DstackTcbInfo};

use crate::attestation::KEY_PROVIDER_EVENT;

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
    /// Expected digest for the key-provider event.
    #[serde_as(as = "Bytes")]
    pub key_provider_event_digest: [u8; 48],
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
    /// $ git rev-parse HEAD
    /// fbdf2e76fb6bd9142277fdd84809de87d86548ef
    ///
    /// See also: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image
    /// Load all supported TCB info measurement sets (e.g., production + dev).
    pub fn from_embedded_tcb_info(
        tcb_info_strings: &[&str],
    ) -> Result<Vec<Self>, MeasurementsError> {
        // Helper closure to parse one TCB info JSON
        let parse_tcb_info = |json_str: &str| -> Result<ExpectedMeasurements, MeasurementsError> {
            let tcb_info: DstackTcbInfo =
                serde_json::from_str(json_str).map_err(|_| MeasurementsError::InvalidTcbInfo)?;

            let decode_measurement =
                |name: &str, hex_value: &str| -> Result<[u8; 48], MeasurementsError> {
                    let decoded = hex::decode(hex_value).map_err(|_| {
                        MeasurementsError::InvalidHexValue(name.into(), hex_value.into())
                    })?;
                    let decoded_len = decoded.len();
                    decoded
                        .try_into()
                        .map_err(|_| MeasurementsError::InvalidLength(name.into(), decoded_len))
                };

            let rtmrs = Measurements {
                rtmr0: decode_measurement("rtmr0", &tcb_info.rtmr0)?,
                rtmr1: decode_measurement("rtmr1", &tcb_info.rtmr1)?,
                rtmr2: decode_measurement("rtmr2", &tcb_info.rtmr2)?,
                mrtd: decode_measurement("mrtd", &tcb_info.mrtd)?,
            };

            let key_provider_events: Vec<&EventLog> = tcb_info
                .event_log
                .iter()
                .filter(|e| e.event == KEY_PROVIDER_EVENT)
                .collect();
            if key_provider_events.len() != 1 {
                return Err(MeasurementsError::InvalidTcbInfo);
            }
            let key_provider_event_digest =
                decode_measurement(KEY_PROVIDER_EVENT, &key_provider_events[0].digest)?;

            Ok(ExpectedMeasurements {
                rtmrs,
                key_provider_event_digest,
            })
        };

        let mut results = vec![];
        for s in tcb_info_strings {
            results.push(parse_tcb_info(s)?);
        }

        Ok(results)
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
