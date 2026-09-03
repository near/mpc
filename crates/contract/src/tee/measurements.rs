use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation;
use near_mpc_contract_interface::types::ExpectedMeasurements;
use near_sdk::log;

use crate::dto_mapping::IntoContractType as _;

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
