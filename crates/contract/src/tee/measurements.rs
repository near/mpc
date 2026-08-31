use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation;
use near_mpc_contract_interface::types::{ExpectedMeasurements, MeasurementVoteAction};
use near_sdk::{log, near};
use std::collections::BTreeMap;

use crate::dto_mapping::IntoContractType as _;
use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};

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

    /// Returns a new [`MeasurementVotes`] containing only votes from current participants.
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

/// Collection of allowed OS measurements. Managed via voting (add requires threshold,
/// remove requires unanimity). Starts empty on fresh contracts (consistent with docker
/// image hashes and launcher hashes); seeded from
/// [`default_measurements()`](mpc_attestation::attestation::default_measurements) on migration.
/// Once populated, at least one measurement must remain.
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct AllowedMeasurements {
    entries: Vec<ExpectedMeasurements>,
}

impl AllowedMeasurements {
    /// Adds a new measurement set to the allowed list.
    /// Returns `false` if the measurement is already in the list.
    pub fn add(&mut self, measurement: ExpectedMeasurements) -> bool {
        if self.entries.contains(&measurement) {
            log!("measurement already in allowed list");
            return false;
        }
        self.entries.push(measurement);
        true
    }

    /// Removes a measurement set from the allowed list.
    /// Returns `false` if the measurement was not found or if removal would leave the list empty.
    pub fn remove(&mut self, measurement: &ExpectedMeasurements) -> bool {
        let would_remain = self.entries.iter().filter(|e| *e != measurement).count();
        if would_remain == 0 {
            return false;
        }
        let len_before = self.entries.len();
        self.entries.retain(|e| e != measurement);
        self.entries.len() < len_before
    }

    /// Returns all allowed measurements.
    pub fn entries(&self) -> &[ExpectedMeasurements] {
        &self.entries
    }

    /// Converts to attestation-crate types for verification.
    pub fn to_attestation_measurements(&self) -> Vec<attestation::ExpectedMeasurements> {
        self.entries
            .iter()
            .cloned()
            .map(|m| m.into_contract_type())
            .collect()
    }
}
