use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation;
use near_mpc_contract_interface::types::{ExpectedMeasurements, MeasurementVoteAction};
use near_sdk::log;

use crate::dto_mapping::IntoContractType as _;
use crate::primitives::votes::ProposalHashEncoding;

impl ProposalHashEncoding for MeasurementVoteAction {
    fn bytes_for_hash(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of MeasurementVoteAction must succeed")
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{ExpectedMeasurements, MeasurementVoteAction};
    use crate::primitives::votes::ProposalHashEncoding;
    use mpc_primitives::hash::{KeyProviderEventDigest, MrtdHash, Rtmr0Hash, Rtmr1Hash, Rtmr2Hash};
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    /// Golden value computed independently (Python hashlib over the borsh bytes:
    /// 1-byte variant tag + the five 48-byte digests), so a change to the encoding
    /// or hashing fails here.
    #[test]
    fn measurement_vote_action_proposal_hash__should_match_sha256_of_borsh_bytes() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let measurement = ExpectedMeasurements {
            mrtd: MrtdHash::from([0xCD; 48]),
            rtmr0: Rtmr0Hash::from([0xCD; 48]),
            rtmr1: Rtmr1Hash::from([0xCD; 48]),
            rtmr2: Rtmr2Hash::from([0xCD; 48]),
            key_provider_event_digest: KeyProviderEventDigest::from([0xCD; 48]),
        };

        // When / Then
        assert_eq!(
            MeasurementVoteAction::Add(measurement).proposal_hash(),
            "179aaa73073c7493dc33b55de9a28735d28f94975b662f22a6aaa63d6c059fcc"
                .parse()
                .unwrap()
        );
    }
}
