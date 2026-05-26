use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::{ExpectedMeasurements, Measurements};
use near_sdk::{log, near};

use crate::primitives::{
    key_state::AuthenticatedParticipantId,
    participants::Participants,
    votes::{ProposalHash, ProposalHashEncoding, Votes},
};
use crate::storage_keys::StorageKey;

mpc_primitives::define_hash!(
    /// SHA-384 digest of the MRTD (Module Run-Time Data) TDX measurement.
    MrtdHash, 48
);
mpc_primitives::define_hash!(
    /// SHA-384 digest of the RTMR0 TDX measurement.
    Rtmr0Hash, 48
);
mpc_primitives::define_hash!(
    /// SHA-384 digest of the RTMR1 TDX measurement.
    Rtmr1Hash, 48
);
mpc_primitives::define_hash!(
    /// SHA-384 digest of the RTMR2 TDX measurement.
    Rtmr2Hash, 48
);
mpc_primitives::define_hash!(
    /// SHA-384 digest of the key provider event.
    KeyProviderEventDigest, 48
);

/// The action a participant is voting for on an OS measurement set.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasurementVoteAction {
    Add(ContractExpectedMeasurements),
    Remove(ContractExpectedMeasurements),
}

impl ProposalHashEncoding for MeasurementVoteAction {
    fn bytes_for_hash(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of MeasurementVoteAction must succeed")
    }
}

/// Hash-based vote store for OS-measurement add/remove proposals.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MeasurementVotes {
    pending: Votes<AuthenticatedParticipantId>,
}

impl Default for MeasurementVotes {
    fn default() -> Self {
        Self {
            pending: Votes::new(
                StorageKey::TeeMeasurementVotesByVoterV1,
                StorageKey::TeeMeasurementVotesByProposalV1,
            ),
        }
    }
}

impl MeasurementVotes {
    /// Records `participant`'s vote for `action`. Returns the count of voters
    /// (still in `participants`) who have voted for the same action.
    pub fn vote(
        &mut self,
        action: MeasurementVoteAction,
        participant: &AuthenticatedParticipantId,
        participants: &Participants,
    ) -> u64 {
        let hash = ProposalHash::from(action);
        let voter_set = self.pending.vote(participant.clone(), hash);
        u64::try_from(
            voter_set.count_for(|v| participants.is_participant_given_participant_id(&v.get())),
        )
        .expect("usize -> u64 conversion never fails on wasm32")
    }

    /// Clears all in-flight measurement votes.
    pub fn clear_votes(&mut self) {
        self.pending.clear();
    }

    /// Drops votes cast by accounts no longer in `participants`.
    pub fn retain_for(&mut self, participants: &Participants) {
        self.pending
            .retain_votes(|v| participants.is_participant_given_participant_id(&v.get()));
    }

    /// Returns a snapshot of the current votes for use by view methods.
    pub fn snapshot(
        &self,
    ) -> std::collections::BTreeMap<
        ProposalHash,
        std::collections::BTreeSet<AuthenticatedParticipantId>,
    > {
        self.pending.all()
    }

    /// True when no in-flight votes are recorded. Used by tests.
    pub fn is_empty(&self) -> bool {
        self.pending.all().is_empty()
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
