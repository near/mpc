//! TODO(#2434): remove this entire module after v3.8.0 migration is deployed
//!
//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{env, store::LookupMap};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::{
        measurements::{AllowedMeasurements, ContractExpectedMeasurements},
        proposal::{
            AllowedDockerImageHashes, AllowedLauncherImages, CodeHashesVotes, LauncherHashVotes,
        },
        tee_state::NodeAttestation,
    },
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StaleData,
};

/// Previous TeeState layout — without `allowed_measurements` and `measurement_votes` fields.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: AllowedDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: CodeHashesVotes,
    launcher_votes: LauncherHashVotes,
    stored_attestations: BTreeMap<near_sdk::PublicKey, NodeAttestation>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: dtos::ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
    metrics: dtos::Metrics,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let crate::ProtocolContractState::Running(_running_state) = &value.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        // Seed on-chain measurements from hardcoded defaults (both prod and dev)
        let allowed_measurements = AllowedMeasurements::from_entries(
            mpc_attestation::attestation::default_measurements()
                .iter()
                .cloned()
                .map(ContractExpectedMeasurements::from)
                .collect(),
        );

        let new_tee_state = crate::tee::tee_state::TeeState {
            allowed_docker_image_hashes: value.tee_state.allowed_docker_image_hashes,
            allowed_launcher_images: value.tee_state.allowed_launcher_images,
            votes: value.tee_state.votes,
            launcher_votes: value.tee_state.launcher_votes,
            stored_attestations: value.tee_state.stored_attestations,
            allowed_measurements,
            measurement_votes: Default::default(),
        };

        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy: value.foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            config: value.config,
            tee_state: new_tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {},
            metrics: value.metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_seeds_measurements_from_defaults() {
        // given
        let defaults = mpc_attestation::attestation::default_measurements();

        // when
        let allowed = AllowedMeasurements::from_entries(
            defaults
                .iter()
                .cloned()
                .map(ContractExpectedMeasurements::from)
                .collect(),
        );

        // then
        assert_eq!(allowed.entries().len(), defaults.len());

        let roundtripped = allowed.to_attestation_measurements();
        for (original, converted) in defaults.iter().zip(roundtripped.iter()) {
            assert_eq!(original.rtmrs.mrtd, converted.rtmrs.mrtd);
            assert_eq!(original.rtmrs.rtmr0, converted.rtmrs.rtmr0);
            assert_eq!(original.rtmrs.rtmr1, converted.rtmrs.rtmr1);
            assert_eq!(original.rtmrs.rtmr2, converted.rtmrs.rtmr2);
            assert_eq!(
                original.key_provider_event_digest,
                converted.key_provider_event_digest
            );
        }
    }
}
