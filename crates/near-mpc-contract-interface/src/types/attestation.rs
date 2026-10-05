use std::fmt;

use crate::types::tee::ExpectedMeasurements;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Constructor;
use mpc_primitives::hash::{
    KeyProviderEventDigest, LauncherDockerComposeHash, MrtdHash, NodeImageHash, Rtmr0Hash,
    Rtmr1Hash, Rtmr2Hash,
};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

/// A variable-length byte vector serialized as a hex string in JSON.
#[serde_as]
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
#[serde(transparent)]
pub struct HexVec(#[serde_as(as = "Hex")] pub Vec<u8>);

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Mock(MockAttestation),
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum VerifiedAttestation {
    Dstack(VerifiedDstackAttestation),
    Mock(MockAttestation),
}

impl VerifiedAttestation {
    /// The stored expiry timestamp, if the attestation carries one.
    /// [`Dstack`](VerifiedAttestation::Dstack) entries always do; a
    /// [`Mock`](VerifiedAttestation::Mock) entry does only when it was stamped
    /// with one. A [`Mock`](VerifiedAttestation::Mock) with no expiry (`None`)
    /// can come from an older contract or from a genesis sentinel, so callers
    /// must not read `None` as "old contract".
    pub fn expiry_timestamp_seconds(&self) -> Option<u64> {
        match self {
            VerifiedAttestation::Dstack(attestation) => Some(attestation.expiry_timestamp_seconds),
            VerifiedAttestation::Mock(attestation) => attestation.expiry_timestamp_seconds(),
        }
    }
}

/// An attestation as the contract stores it.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct StoredAttestation {
    pub attestation: VerifiedAttestation,
    /// Block time at which the contract accepted this attestation. Every accepted submission
    /// restamps it, so a submitter can tell whether its own submission landed. `None` for an
    /// entry stored before the contract recorded it.
    pub accepted_at_seconds: Option<u64>,
}

/// What `get_attestation` returns. Nodes are upgraded before the contract, so a node has to read
/// both the current shape and the one that predates
/// [`StoredAttestation::accepted_at_seconds`].
///
/// TODO(#4498): collapse into [`StoredAttestation`] once every deployed contract stamps it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAttestationResponse {
    Current(StoredAttestation),
    Legacy(VerifiedAttestation),
}

impl GetAttestationResponse {
    pub fn attestation(&self) -> &VerifiedAttestation {
        match self {
            GetAttestationResponse::Current(stored) => &stored.attestation,
            GetAttestationResponse::Legacy(attestation) => attestation,
        }
    }

    /// `None` both for an entry the contract reports without an acceptance time and for a
    /// [`Legacy`](GetAttestationResponse::Legacy) response, which has no such field at all.
    pub fn accepted_at_seconds(&self) -> Option<u64> {
        match self {
            GetAttestationResponse::Current(stored) => stored.accepted_at_seconds,
            GetAttestationResponse::Legacy(_) => None,
        }
    }
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifiedDstackAttestation {
    /// The digest of the MPC image running.
    pub mpc_image_hash: NodeImageHash,
    /// The digest of the launcher compose file running.
    pub launcher_compose_hash: LauncherDockerComposeHash,
    /// Unix time stamp for when this attestation expires.
    pub expiry_timestamp_seconds: u64,
    /// The OS measurements that were verified during initial attestation.
    pub measurements: VerifiedMeasurements,
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifiedMeasurements {
    pub mrtd: MrtdHash,
    pub rtmr0: Rtmr0Hash,
    pub rtmr1: Rtmr1Hash,
    pub rtmr2: Rtmr2Hash,
    pub key_provider_event_digest: KeyProviderEventDigest,
}

#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Constructor,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DstackAttestation {
    pub quote: HexVec,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
}

#[expect(clippy::large_enum_variant)]
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum MockAttestation {
    /// Always pass validation
    Valid,
    /// Always fails validation
    Invalid,
    /// Pass validation depending on the set constraints
    WithConstraints {
        mpc_docker_image_hash: Option<NodeImageHash>,
        launcher_docker_compose_hash: Option<LauncherDockerComposeHash>,
        /// Unix time stamp for when this attestation expires.
        expiry_timestamp_seconds: Option<u64>,
        expected_measurements: Option<ExpectedMeasurements>,
    },
}

impl MockAttestation {
    /// The configured expiry timestamp, if any. [`Valid`](MockAttestation::Valid)
    /// and [`Invalid`](MockAttestation::Invalid) never carry one.
    pub fn expiry_timestamp_seconds(&self) -> Option<u64> {
        match self {
            MockAttestation::WithConstraints {
                expiry_timestamp_seconds,
                ..
            } => *expiry_timestamp_seconds,
            MockAttestation::Valid | MockAttestation::Invalid => None,
        }
    }
}

// TODO(#3494): superseded by `tee_verifier_interface::Collateral`; remove
// this serde-carrying copy once `mpc-contract` consumes the Borsh mirrors.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Collateral {
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: HexVec,
    pub pck_crl: HexVec,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: HexVec,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: HexVec,
    pub pck_certificate_chain: Option<String>,
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

/// Trusted Computing Base information structure
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
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

/// Represents an event log entry in the system
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    const ACCEPTED_AT_SECONDS: u64 = 1_800_000_000;
    const EXPIRES_AT_SECONDS: u64 = 1_800_604_800;

    fn mock() -> VerifiedAttestation {
        VerifiedAttestation::Mock(MockAttestation::Valid)
    }

    fn mock_with_constraints() -> VerifiedAttestation {
        VerifiedAttestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(EXPIRES_AT_SECONDS),
            expected_measurements: None,
        })
    }

    /// Its hash fields serialize as hex strings through a hand-written impl, which
    /// `#[serde(untagged)]` replays out of a buffered `Content` rather than straight off the wire.
    fn dstack() -> VerifiedAttestation {
        VerifiedAttestation::Dstack(VerifiedDstackAttestation {
            mpc_image_hash: [0x11; 32].into(),
            launcher_compose_hash: [0x22; 32].into(),
            expiry_timestamp_seconds: EXPIRES_AT_SECONDS,
            measurements: VerifiedMeasurements {
                mrtd: [0x33; 48].into(),
                rtmr0: [0x44; 48].into(),
                rtmr1: [0x55; 48].into(),
                rtmr2: [0x66; 48].into(),
                key_provider_event_digest: [0x77; 48].into(),
            },
        })
    }

    #[rstest]
    fn get_attestation_response__should_read_a_current_response(
        #[values(mock(), mock_with_constraints(), dstack())] attestation: VerifiedAttestation,
        #[values(Some(ACCEPTED_AT_SECONDS), None)] accepted_at_seconds: Option<u64>,
    ) {
        // Given: an entry the current contract stores, stamped or carried over by the migration
        let stored = StoredAttestation {
            attestation,
            accepted_at_seconds,
        };
        let response = serde_json::to_string(&stored).unwrap();

        // When
        let parsed: GetAttestationResponse = serde_json::from_str(&response).unwrap();

        // Then
        assert_eq!(parsed, GetAttestationResponse::Current(stored));
    }

    #[rstest]
    fn get_attestation_response__should_read_a_response_from_a_contract_without_the_timestamp(
        #[values(mock(), mock_with_constraints(), dstack())] attestation: VerifiedAttestation,
    ) {
        // Given
        let response = serde_json::to_string(&attestation).unwrap();

        // When
        let parsed: GetAttestationResponse = serde_json::from_str(&response).unwrap();

        // Then
        assert_eq!(parsed, GetAttestationResponse::Legacy(attestation));
    }
}
