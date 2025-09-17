use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Constructor, Deref, From};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::crypto::Ed25519PublicKey;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Mock(MockAttestation),
}

#[derive(Clone, Constructor, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DstackAttestation {
    pub quote: Quote,
    pub collateral: Collateral,
    // TODO: This type should be defined within the crate to remove dependency to dstack.
    pub tcb_info: TcbInfo,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum MockAttestation {
    #[default]
    /// Always pass validation
    Valid,
    /// Always fails validation
    Invalid,
    /// Pass validation depending on the set constraints
    WithConstraints {
        mpc_docker_image_hash: Option<MpcDockerImageHash>,
        launcher_docker_compose_hash: Option<LauncherDockerComposeHash>,
        /// Unix time stamp for when this attestation expires.  
        expiry_time_stamp_seconds: Option<u64>,
    },
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
// #[cfg_attr(
//     all(feature = "abi", not(target_arch = "wasm32")),
//     derive(schemars::JsonSchema)
// )]
pub struct Collateral {
    pub pck_crl_issuer_chain: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub root_ca_crl: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub qe_identity_signature: Vec<u8>,
}

impl From<Collateral> for dcap_qvl::QuoteCollateralV3 {
    fn from(collateral: Collateral) -> Self {
        let Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
        } = collateral;

        dcap_qvl::QuoteCollateralV3 {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
        }
    }
}

impl fmt::Debug for DstackAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_BYTES: usize = 2048;

        fn truncate_debug<T: fmt::Debug>(value: &T, max_bytes: usize) -> String {
            let debug_str = format!("{:?}", value);
            if debug_str.len() <= max_bytes {
                debug_str
            } else {
                format!(
                    "{}... (truncated {} bytes)",
                    &debug_str[..max_bytes],
                    debug_str.len() - max_bytes
                )
            }
        }

        f.debug_struct("DstackAttestation")
            .field("quote", &truncate_debug(&self.quote, MAX_BYTES))
            .field("collateral", &truncate_debug(&self.collateral, MAX_BYTES))
            .field("tcb_info", &truncate_debug(&self.tcb_info, MAX_BYTES))
            .finish()
    }
}

/// Helper struct to deserialize the `app_compose` JSON from TCB info. This is a workaround due to
/// current limitations in the Dstack SDK.
///
/// See: https://github.com/Dstack-TEE/dstack/issues/267
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    pub runner: String,
    pub docker_compose_file: DockerComposeString,
    pub kms_enabled: bool,
    pub tproxy_enabled: Option<bool>,
    pub gateway_enabled: Option<bool>,
    pub public_logs: bool,
    pub public_sysinfo: bool,
    pub local_key_provider_enabled: bool,
    pub key_provider_id: Option<String>,
    pub allowed_envs: Vec<String>,
    pub no_instance_id: bool,
    pub secure_time: Option<bool>,
    pub pre_launch_script: Option<String>,
    // The following fields that don't have any security implication are omitted:
    //
    // - docker_config: JsonValue,
    // - public_tcbinfo: bool,
}

/// Trusted Computing Base information structure
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct TcbInfo {
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

impl From<dstack_sdk::dstack_client::TcbInfo> for TcbInfo {
    fn from(tcb_info: dstack_sdk::dstack_client::TcbInfo) -> Self {
        let dstack_sdk::dstack_client::TcbInfo {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            os_image_hash,
            compose_hash,
            device_id,
            app_compose,
            event_log,
        } = tcb_info;

        let event_log = event_log.into_iter().map(EventLog::from).collect();

        TcbInfo {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            os_image_hash,
            compose_hash,
            device_id,
            app_compose,
            event_log,
        }
    }
}

/// Represents an event log entry in the system
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct EventLog {
    /// The index of the IMR (Integrity Measurement Register)
    pub imr: u32,
    /// The type of event being logged
    pub event_type: u32,
    /// The cryptographic digest of the event
    pub digest: String,
    /// The type of event as a string
    pub event: String,
    /// The payload data associated with the event
    pub event_payload: String,
}

impl From<dstack_sdk::dstack_client::EventLog> for EventLog {
    fn from(event_log: dstack_sdk::dstack_client::EventLog) -> Self {
        let dstack_sdk::dstack_client::EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = event_log;

        EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        }
    }
}

/// A type that contains a docker compose the contents of a docker compose file as
/// a string.
///
/// This type does currently not do any validation of the string
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, From, Deref)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DockerComposeString(String);

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, From, Deref)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Quote(
    // TODO: schema_rs fails with attributes.
    // #[serde(with = "serde_bytes")]
    Vec<u8>,
);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[repr(u16)]
#[borsh(use_discriminant = true)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum ReportDataVersion {
    V1 = 1,
}

#[derive(Debug, Clone, Constructor)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ReportDataV1 {
    pub tls_public_key: Ed25519PublicKey,
}

const BINARY_VERSION_SIZE: usize = 2;

impl ReportDataVersion {
    pub fn to_be_bytes(self) -> [u8; BINARY_VERSION_SIZE] {
        (self as u16).to_be_bytes()
    }

    pub fn from_be_bytes(bytes: [u8; BINARY_VERSION_SIZE]) -> Option<Self> {
        match u16::from_be_bytes(bytes) {
            1 => Some(Self::V1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReportData {
    V1(ReportDataV1),
}
