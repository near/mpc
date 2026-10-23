#[cfg(feature = "borsh-schema")]
use alloc::string::ToString;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

/// Required measurements for TEE attestation verification (a.k.a. RTMRs checks). These values
/// define the trusted baseline that TEE environments must match during verification. They
/// should be updated when the underlying TEE environment changes.
///
/// To learn more about the RTMRs, see:
/// - <https://docs.phala.network/phala-cloud/tees-attestation-and-zero-trust-security/attestation#runtime-measurement-fields>
/// - <https://arxiv.org/pdf/2303.15540> (Section 9.1)
#[serde_as]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct Measurements {
    /// MRTD (Measurement Register for the Trust Domain) - identifies the virtual firmware.
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct ExpectedMeasurements {
    /// Expected RTMRs (Runtime Measurement Registers).
    pub rtmrs: Measurements,
    /// Expected digest for the key-provider event.
    #[serde_as(as = "Bytes")]
    pub key_provider_event_digest: [u8; 48],
}

impl From<&crate::tcb_info::TcbInfo> for Measurements {
    fn from(tcb: &crate::tcb_info::TcbInfo) -> Self {
        Self {
            mrtd: *tcb.mrtd,
            rtmr0: *tcb.rtmr0,
            rtmr1: *tcb.rtmr1,
            rtmr2: *tcb.rtmr2,
        }
    }
}
