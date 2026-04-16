use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::{ExpectedMeasurements, Measurements};
use near_sdk::{log, near};

use crate::primitives::{key_state::AuthenticatedParticipantId, votes::Votes};

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

pub type MeasurementVotes = Votes<AuthenticatedParticipantId, MeasurementVoteAction>;

/// The action a participant is voting for on an OS measurement set.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
}

/// On-chain representation of expected TDX measurements.
/// Mirrors [`mpc_attestation::attestation::ExpectedMeasurements`] with
/// contract-compatible serialization (hex strings in JSON, borsh for storage).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
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
