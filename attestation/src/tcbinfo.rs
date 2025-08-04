use alloc::{string::String, vec::Vec};
use derive_more::{Deref, From, Into};
use serde::{Deserialize, Serialize};

use crate::attestation::EventLog;

/// Trusted Computing Base information structure
///
/// It was copy-pasted from [the Dstack Rust SDK][1] instead of using it directly because using the
/// Rust SDK directly would pull in dependencies that are not allowed in smart contract code (like
/// tokio and mio).
///
/// [1]: https://github.com/Dstack-TEE/dstack/blob/f6b0927cefd94c0e003ae2789c95b78ed86580bf/sdk/rust/src/dstack_client.rs#L168-L192
#[derive(Serialize, Deserialize)]
pub struct DstackTcbInfo {
    /// The measurement root of trust
    pub mrtd: String,
    /// The value of RTMR0 (Runtime Measurement Register 0)
    pub rtmr0: String,
    /// The value of RTMR1 (Runtime Measurement Register 1)
    pub rtmr1: String,
    /// The value of RTMR2 (Runtime Measurement Register 2)
    pub rtmr2: String,
    /// The value of RTMR3 (Runtime Measurement Register 3)
    pub rtmr3: String,
    /// The hash of the OS image. This is empty if the OS image is not measured by KMS.
    #[serde(default)]
    pub os_image_hash: String,
    /// The hash of the compose configuration
    pub compose_hash: String,
    /// The device identifier
    pub device_id: String,
    /// The app compose
    pub app_compose: String,
    /// The event log entries
    pub event_log: Vec<EventLog>,
}

/// Dstack event log, a.k.a. the TCB Info.
#[derive(Serialize, Deserialize, From, Deref, Into)]
pub struct TcbInfo(DstackTcbInfo);
