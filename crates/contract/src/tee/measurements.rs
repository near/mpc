use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::{ExpectedMeasurements, Measurements};
use near_sdk::{log, near};
use std::collections::BTreeMap;

use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};

pub struct MrtdHashMarker;
/// SHA-384 digest of the MRTD (Module Run-Time Data) TDX measurement.
pub type MrtdHash = mpc_primitives::hash::Hash<MrtdHashMarker, 48>;

pub struct Rtmr0HashMarker;
/// SHA-384 digest of the RTMR0 TDX measurement.
pub type Rtmr0Hash = mpc_primitives::hash::Hash<Rtmr0HashMarker, 48>;

pub struct Rtmr1HashMarker;
/// SHA-384 digest of the RTMR1 TDX measurement.
pub type Rtmr1Hash = mpc_primitives::hash::Hash<Rtmr1HashMarker, 48>;

pub struct Rtmr2HashMarker;
/// SHA-384 digest of the RTMR2 TDX measurement.
pub type Rtmr2Hash = mpc_primitives::hash::Hash<Rtmr2HashMarker, 48>;

pub struct KeyProviderEventDigestMarker;
/// SHA-384 digest of the key provider event.
pub type KeyProviderEventDigest = mpc_primitives::hash::Hash<KeyProviderEventDigestMarker, 48>;

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

    /// Returns a new `MeasurementVotes` containing only votes from current participants.
    pub fn get_remaining_votes(&self, participants: &Participants) -> Self {
        let remaining = self
            .vote_by_account
            .iter()
            .filter(|(participant_id, _)| {
                participants.is_participant_given_participant_id(&participant_id.get())
            })
            .map(|(participant_id, vote)| (participant_id.clone(), vote.clone()))
            .collect();
        MeasurementVotes {
            vote_by_account: remaining,
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

/// On-chain representation of expected TDX measurements.
/// Mirrors [`mpc_attestation::attestation::ExpectedMeasurements`] with
/// contract-compatible serialization (hex strings in JSON, borsh for storage).
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
    pub mrtd: MrtdHash,
    pub rtmr0: Rtmr0Hash,
    pub rtmr1: Rtmr1Hash,
    pub rtmr2: Rtmr2Hash,
    pub key_provider_event_digest: KeyProviderEventDigest,
}

impl From<ExpectedMeasurements> for ContractExpectedMeasurements {
    fn from(m: ExpectedMeasurements) -> Self {
        Self {
            mrtd: MrtdHash::from(m.rtmrs.mrtd),
            rtmr0: Rtmr0Hash::from(m.rtmrs.rtmr0),
            rtmr1: Rtmr1Hash::from(m.rtmrs.rtmr1),
            rtmr2: Rtmr2Hash::from(m.rtmrs.rtmr2),
            key_provider_event_digest: KeyProviderEventDigest::from(m.key_provider_event_digest),
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
