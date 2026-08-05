//! Benchmark methods for testing [`crate::primitives::participants::Participants`] performance.
//!
//! These methods expose individual `Participants` operations as contract endpoints
//! so that sandbox tests can measure actual on-chain gas costs for each operation.
//! This enables detecting performance regressions when changing internal data structures.

use crate::MpcContract;
use crate::primitives::participants::ParticipantInfo;
use crate::tee::tee_state::{NodeAttestation, NodeId};
use mpc_attestation::attestation::{
    MockAttestation, ValidatedDstackAttestation, VerifiedAttestation, default_measurements,
};
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_sdk::near;

// Import the generated extension trait from near
use crate::MpcContractExt;

#[near]
impl MpcContract {
    /// Benchmark: Returns the number of participants.
    ///
    /// This serves as a **baseline measurement** for gas costs. The operation
    /// only loads the contract state and calls `.len()` on the participants list.
    /// Comparing other benchmark results against this baseline helps isolate
    /// the cost of specific lookup operations from the fixed cost of state loading.
    pub fn bench_participants_len(&self) -> usize {
        self.protocol_state.active_participants().len()
    }

    /// Benchmark: Check if an account is a participant using `is_participant()`.
    ///
    /// Measures the gas cost of the membership check operation. With the current
    /// `Vec`-based `Participants` implementation, this is an **O(n)** linear scan.
    /// This benchmark helps detect if switching to a different data structure
    /// (e.g., `HashMap`) would improve performance for large participant sets.
    pub fn bench_is_participant(&self, account_id: dtos::AccountId) -> bool {
        let account_id: AccountId = account_id.clone();
        self.protocol_state
            .active_participants()
            .is_participant_given_account_id(&account_id)
    }

    /// Benchmark: Get participant info using `info()`.
    ///
    /// Measures the gas cost of retrieving full `ParticipantInfo` for an account.
    /// Similar to `is_participant()`, this is an **O(n)** operation with the
    /// current `Vec`-based implementation. Returns `true` if info was found.
    ///
    /// This operation is used when the contract needs to access participant
    /// metadata (e.g., `tls_public_key`, `url`) rather than just checking membership.
    pub fn bench_participant_info(&self, account_id: dtos::AccountId) -> bool {
        let account_id: AccountId = account_id.clone();
        self.protocol_state
            .active_participants()
            .info(&account_id)
            .is_some()
    }

    /// Benchmark: Validate participants using `validate()`.
    ///
    /// Measures the gas cost of running validation checks on the participant set.
    /// Validation typically checks for invariants like:
    /// - No duplicate account IDs
    /// - Valid participant IDs (sequential, starting from 1)
    /// - Non-empty participant list
    ///
    /// Returns `true` if valid, `false` otherwise.
    pub fn bench_participants_validate(&self) -> bool {
        self.protocol_state.active_participants().validate().is_ok()
    }

    /// Benchmark: Serialize participants to Borsh bytes and return length.
    ///
    /// Measures the gas cost of Borsh serialization for the entire participant set.
    /// This is relevant because:
    /// - Contract state is serialized/deserialized on every call
    /// - Larger serialized size means higher storage costs
    /// - Serialization overhead can dominate gas costs for large data structures
    ///
    /// Returns the byte length of the serialized `Participants` struct.
    /// Use this to track how serialization cost scales with participant count.
    pub fn bench_participants_serialization_size(&self) -> usize {
        let participants = self.protocol_state.active_participants();
        borsh::to_vec(participants).unwrap().len()
    }

    /// Benchmark: Insert a new participant using `insert()`.
    ///
    /// Measures the gas cost of adding a participant to the set.
    /// Returns the new participant count.
    pub fn bench_participants_insert(&mut self) -> usize {
        let participants = self.protocol_state.active_participants_mut();
        let next_id = participants.next_id();
        let account_id: AccountId = format!("bench-participant-{}.near", next_id.0)
            .parse()
            .unwrap();
        let info = ParticipantInfo {
            tls_public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
                .parse()
                .unwrap(),
            url: "http://bench.test".to_string(),
        };
        participants.insert(account_id, info).unwrap();
        participants.len()
    }

    /// Benchmark: Update participant info using `update_info()`.
    ///
    /// Measures the gas cost of finding and updating a participant's info.
    ///
    /// Returns `true` if update succeeded.
    pub fn bench_participants_update_info(&mut self, account_id: dtos::AccountId) -> bool {
        let account_id: AccountId = account_id.clone();
        let new_info = ParticipantInfo {
            tls_public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
                .parse()
                .unwrap(),
            url: "http://updated.test".to_string(),
        };
        self.protocol_state
            .active_participants_mut()
            .update_info(account_id, new_info)
            .is_ok()
    }

    /// Benchmark: seeds `count` entries into `stored_attestations`, keyed by a synthetic TLS
    /// key derived from `offset + i` so successive calls with disjoint offsets accumulate.
    ///
    /// Bypasses `add_participant` (and thus DCAP verification) so a backlog of arbitrary
    /// size can be created in a few transactions. `expired` selects between a `Dstack`
    /// entry that `clean_invalid_attestations` removes and an unconstrained `Mock` entry it
    /// keeps — the latter isolates the per-entry scan cost paid for surviving entries.
    /// Returns the resulting map size.
    pub fn bench_seed_attestations(&mut self, offset: u32, count: u32, expired: bool) -> u32 {
        let measurements = default_measurements()[0].clone();
        let verified_attestation = if expired {
            VerifiedAttestation::Dstack(ValidatedDstackAttestation {
                mpc_image_hash: [7u8; 32].into(),
                launcher_compose_hash: [8u8; 32].into(),
                expiry_timestamp_seconds: 1,
                measurements,
            })
        } else {
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: None,
                launcher_docker_compose_hash: None,
                expiry_timestamp_seconds: Some(u64::MAX),
                expected_measurements: None,
            })
        };

        for i in offset..offset + count {
            let mut key_bytes = [0u8; 32];
            key_bytes[..4].copy_from_slice(&i.to_le_bytes());
            let tls_public_key: dtos::Ed25519PublicKey = key_bytes.into();
            let account_id: AccountId = format!("bench-attested-{i}.near").parse().unwrap();
            self.tee_state.stored_attestations.insert(
                tls_public_key.clone(),
                NodeAttestation {
                    node_id: NodeId {
                        account_id,
                        tls_public_key: tls_public_key.clone(),
                        account_public_key: tls_public_key,
                    },
                    verified_attestation: verified_attestation.clone(),
                },
            );
        }
        self.tee_state.stored_attestations.len()
    }
}
