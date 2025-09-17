use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Constructor, Deref, From};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Collateral {
    pub pck_crl_issuer_chain: String,
    // #[serde(with = "serde_bytes")]
    pub root_ca_crl: Vec<u8>,
    // #[serde(with = "serde_bytes")]
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    // #[serde(with = "serde_bytes")]
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    // #[serde(with = "serde_bytes")]
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
    tls_public_key: Ed25519PublicKey,
}

use sha3::{Digest, Sha3_384};

/// Number of bytes for the report data.
const REPORT_DATA_SIZE: usize = 64;

/// Common constants for all [`ReportData`] versions.
const BINARY_VERSION_OFFSET: usize = 0;
const BINARY_VERSION_SIZE: usize = 2;

/// report_data_v1: [u8; 64] =
///   [version(2 bytes big endian) || sha384(TLS pub key) || zero padding]
impl ReportDataV1 {
    /// V1-specific format constants
    const PUBLIC_KEYS_OFFSET: usize = BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE;
    const PUBLIC_KEYS_HASH_SIZE: usize = 48;

    // Compile-time assertions for V1 format.
    const _V1_LAYOUT_CHECK: () = {
        assert!(
            BINARY_VERSION_SIZE + Self::PUBLIC_KEYS_HASH_SIZE <= REPORT_DATA_SIZE,
            "V1: Version and public key must not exceed report data size."
        );
    };

    /// Generates the binary representation of V1 report data.
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        let mut report_data = [0u8; REPORT_DATA_SIZE];

        // Copy binary version (2 bytes, big endian)
        let version_bytes = ReportDataVersion::V1.to_be_bytes();
        report_data[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE]
            .copy_from_slice(&version_bytes);

        // Generate and copy hash of public keys
        let public_keys_hash = self.public_keys_hash();
        report_data
            [Self::PUBLIC_KEYS_OFFSET..Self::PUBLIC_KEYS_OFFSET + Self::PUBLIC_KEYS_HASH_SIZE]
            .copy_from_slice(&public_keys_hash);

        // Remaining bytes are already zero-padded by default
        report_data
    }

    /// Parses V1 report data from bytes. Returns the hash of public keys.
    /// Note: This only extracts the hash, not the original public keys.
    pub fn from_bytes(bytes: &[u8; REPORT_DATA_SIZE]) -> [u8; Self::PUBLIC_KEYS_HASH_SIZE] {
        // Extract hash using V1 format
        let mut hash = [0u8; Self::PUBLIC_KEYS_HASH_SIZE];
        hash.copy_from_slice(
            &bytes
                [Self::PUBLIC_KEYS_OFFSET..Self::PUBLIC_KEYS_OFFSET + Self::PUBLIC_KEYS_HASH_SIZE],
        );
        hash
    }

    /// Generates SHA3-384 hash of TLS public key only.
    fn public_keys_hash(&self) -> [u8; Self::PUBLIC_KEYS_HASH_SIZE] {
        let mut hasher = Sha3_384::new();
        hasher.update(&self.tls_public_key);
        hasher.finalize().into()
    }
}

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

impl ReportData {
    pub fn new(tls_public_key: Ed25519PublicKey) -> Self {
        ReportData::V1(ReportDataV1::new(tls_public_key))
    }

    pub fn version(&self) -> ReportDataVersion {
        match self {
            ReportData::V1(_) => ReportDataVersion::V1,
        }
    }

    /// Generates the binary representation of report data.
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        match self {
            ReportData::V1(v1) => v1.to_bytes(),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::report_data::ReportData;
//     use dcap_qvl::quote::Quote;
//     use k256::elliptic_curve::rand_core::OsRng;
//     use test_utils::attestation::{DstackAttestationTestUtils, mock_dstack_attestation};

//     #[test]
//     fn test_from_str_valid() {
//         let attestation = mock_dstack_attestation();
//         let quote = Quote::parse(&attestation.quote).unwrap();

//         let td_report = quote.report.as_td10().expect("Should be a TD 1.0 report");
//         let tls_key = attestation.p2p_tls_public_key();
//         let report_data = ReportData::V1(ReportDataV1::new(tls_key));

//         assert_eq!(report_data.to_bytes(), td_report.report_data,);
//     }

//     fn create_test_key() -> ed25519_dalek::VerifyingKey {
//         ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key()
//     }

//     #[test]
//     fn test_binary_version_serialization() {
//         let version = ReportDataVersion::V1;
//         assert_eq!(version.to_be_bytes(), [0, 1]);

//         let parsed = ReportDataVersion::from_be_bytes([0, 1]).unwrap();
//         assert_eq!(parsed, ReportDataVersion::V1);

//         assert!(ReportDataVersion::from_be_bytes([0, 2]).is_none());
//     }

//     #[test]
//     fn test_report_data_enum_structure() {
//         let tls_key = create_test_key();
//         let data = ReportData::V1(ReportDataV1::new(tls_key.clone()));

//         match &data {
//             ReportData::V1(v1) => {
//                 assert_eq!(&v1.tls_public_key, &tls_key);
//             }
//         }

//         assert_eq!(data.version(), ReportDataVersion::V1);
//     }

//     #[test]
//     fn test_report_data_v1_struct() {
//         let tls_key = create_test_key();

//         let v1 = ReportDataV1::new(tls_key.clone());
//         assert_eq!(v1.tls_public_key, tls_key);
//     }

//     #[test]
//     fn test_from_bytes() {
//         let tls_key = create_test_key();
//         let report_data_v1 = ReportDataV1::new(tls_key);
//         let bytes = report_data_v1.to_bytes();

//         let hash = ReportDataV1::from_bytes(&bytes);
//         assert_eq!(hash, report_data_v1.public_keys_hash());

//         let report_data = ReportData::V1(report_data_v1);
//         assert_eq!(report_data.to_bytes(), bytes);
//     }

//     #[test]
//     fn test_binary_version_placement() {
//         let tls_key = create_test_key();
//         let bytes = ReportDataV1::new(tls_key).to_bytes();

//         let version_bytes =
//             &bytes[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE];
//         assert_eq!(version_bytes, &[0, 1]);
//     }

//     #[test]
//     fn test_public_key_hash_placement() {
//         let tls_key = create_test_key();
//         let report_data_v1 = ReportDataV1::new(tls_key.clone());
//         let bytes = report_data_v1.to_bytes();

//         let report_data = ReportData::V1(report_data_v1);
//         assert_eq!(report_data.to_bytes(), bytes);

//         let hash_bytes = &bytes[ReportDataV1::PUBLIC_KEYS_OFFSET
//             ..ReportDataV1::PUBLIC_KEYS_OFFSET + ReportDataV1::PUBLIC_KEYS_HASH_SIZE];
//         assert_ne!(hash_bytes, &[0u8; ReportDataV1::PUBLIC_KEYS_HASH_SIZE]);

//         let mut hasher = Sha3_384::new();
//         // Skip first byte as it is used for identifier for the curve type.
//         let key_data = &tls_key.as_bytes()[1..];
//         hasher.update(key_data);
//         let expected: [u8; ReportDataV1::PUBLIC_KEYS_HASH_SIZE] = hasher.finalize().into();

//         assert_eq!(hash_bytes, &expected);
//     }

//     #[test]
//     fn test_zero_padding() {
//         let tls_key = create_test_key();
//         let bytes = ReportDataV1::new(tls_key).to_bytes();

//         let padding =
//             &bytes[ReportDataV1::PUBLIC_KEYS_OFFSET + ReportDataV1::PUBLIC_KEYS_HASH_SIZE..];
//         assert!(padding.iter().all(|&b| b == 0));
//     }

//     #[test]
//     fn test_report_data_size() {
//         let tls_key = create_test_key();
//         let bytes = ReportDataV1::new(tls_key);
//         assert_eq!(bytes.to_bytes().len(), REPORT_DATA_SIZE);
//     }
// }
