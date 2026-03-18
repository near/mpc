use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::{ExpectedMeasurements, Measurements};
use near_sdk::{log, near};
use serde_with::serde_as;
use std::collections::BTreeMap;

use crate::primitives::key_state::AuthenticatedParticipantId;

/// A 48-byte digest serialized as hex in JSON and raw bytes in borsh.
#[serde_as]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema, schemars::JsonSchema)
)]
#[serde(transparent)]
pub struct Sha384Digest {
    #[serde_as(as = "serde_with::hex::Hex")]
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "String") // Schemars doesn't support arrays >32; actual JSON is a hex string.
    )]
    bytes: [u8; 48],
}

impl From<[u8; 48]> for Sha384Digest {
    fn from(bytes: [u8; 48]) -> Self {
        Self { bytes }
    }
}

impl From<Sha384Digest> for [u8; 48] {
    fn from(digest: Sha384Digest) -> Self {
        digest.bytes
    }
}

/// On-chain representation of expected TDX measurements.
/// Mirrors [`mpc_attestation::attestation::ExpectedMeasurements`] with
/// contract-compatible serialization (hex strings in JSON, borsh for storage).
#[serde_as]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema, schemars::JsonSchema)
)]
pub struct ContractExpectedMeasurements {
    pub mrtd: Sha384Digest,
    pub rtmr0: Sha384Digest,
    pub rtmr1: Sha384Digest,
    pub rtmr2: Sha384Digest,
    pub key_provider_event_digest: Sha384Digest,
}

impl From<ExpectedMeasurements> for ContractExpectedMeasurements {
    fn from(m: ExpectedMeasurements) -> Self {
        Self {
            mrtd: Sha384Digest::from(m.rtmrs.mrtd),
            rtmr0: Sha384Digest::from(m.rtmrs.rtmr0),
            rtmr1: Sha384Digest::from(m.rtmrs.rtmr1),
            rtmr2: Sha384Digest::from(m.rtmrs.rtmr2),
            key_provider_event_digest: Sha384Digest::from(m.key_provider_event_digest),
        }
    }
}

impl From<ContractExpectedMeasurements> for ExpectedMeasurements {
    fn from(m: ContractExpectedMeasurements) -> Self {
        Self {
            rtmrs: Measurements {
                mrtd: m.mrtd.into(),
                rtmr0: m.rtmr0.into(),
                rtmr1: m.rtmr1.into(),
                rtmr2: m.rtmr2.into(),
            },
            key_provider_event_digest: m.key_provider_event_digest.into(),
        }
    }
}

/// The action a participant is voting for on an OS measurement set.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasurementVoteAction {
    Add(ContractExpectedMeasurements),
    Remove(ContractExpectedMeasurements),
}

/// Tracks votes for adding or removing OS measurements.
/// Each participant can have at most one active vote at a time.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeasurementVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, MeasurementVoteAction>,
}

impl MeasurementVotes {
    /// Casts a vote for the given action and returns the total number of participants
    /// who have voted for the same action. Replaces any previous vote by this participant.
    pub fn vote(
        &mut self,
        action: MeasurementVoteAction,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .vote_by_account
            .insert(participant.clone(), action.clone())
            .is_some()
        {
            log!("removed old measurement vote for signer");
        }
        let total = self.count_votes(&action);
        log!("total measurement votes for action: {}", total);
        total
    }

    /// Counts the total number of participants who have voted for the given action.
    fn count_votes(&self, action: &MeasurementVoteAction) -> u64 {
        u64::try_from(
            self.vote_by_account
                .values()
                .filter(|a| *a == action)
                .count(),
        )
        .expect("participant count should not overflow u64")
    }

    /// Clears all measurement votes.
    pub fn clear_votes(&mut self) {
        self.vote_by_account.clear();
    }
}

/// Collection of allowed OS measurements. Managed via voting (add requires threshold,
/// remove requires unanimity). Starts empty on fresh contracts (consistent with docker
/// image hashes and launcher hashes); seeded from `default_measurements()` on migration.
/// Once populated, at least one measurement must remain.
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct AllowedMeasurements {
    entries: Vec<ContractExpectedMeasurements>,
}

impl AllowedMeasurements {
    /// Adds a new measurement set to the allowed list.
    /// Returns `false` if the measurement is already in the list.
    pub fn add(&mut self, measurement: ContractExpectedMeasurements) -> bool {
        if self.entries.contains(&measurement) {
            log!("measurement already in allowed list");
            return false;
        }
        self.entries.push(measurement);
        true
    }

    /// Removes a measurement set from the allowed list.
    /// Returns `false` if the measurement was not found or if removal would leave the list empty.
    pub fn remove(&mut self, measurement: &ContractExpectedMeasurements) -> bool {
        let would_remain = self.entries.iter().filter(|e| *e != measurement).count();
        if would_remain == 0 {
            return false;
        }
        let len_before = self.entries.len();
        self.entries.retain(|e| e != measurement);
        self.entries.len() < len_before
    }

    /// Returns all allowed measurements.
    pub fn entries(&self) -> &[ContractExpectedMeasurements] {
        &self.entries
    }

    /// Converts to attestation-crate types for verification.
    pub fn to_attestation_measurements(&self) -> Vec<ExpectedMeasurements> {
        self.entries
            .iter()
            .cloned()
            .map(ExpectedMeasurements::from)
            .collect()
    }

    /// Creates from a list of entries (for migration).
    /// TODO(#2434): remove after migration is deployed
    pub fn from_entries(entries: Vec<ContractExpectedMeasurements>) -> Self {
        Self { entries }
    }
}
