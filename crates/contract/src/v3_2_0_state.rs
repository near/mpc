//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::BorshDeserialize;
use mpc_attestation::attestation::Attestation;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{
    env,
    store::{IterableMap, LookupMap},
};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes},
        tee_state::NodeId,
    },
    update::ProposedUpdates,
    Config,
};

#[derive(Debug, BorshDeserialize)]
struct TeeState {
    _allowed_docker_image_hashes: AllowedDockerImageHashes,
    _allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    _votes: CodeHashesVotes,
    participants_attestations: IterableMap<near_sdk::PublicKey, (NodeId, Attestation)>,
}

#[derive(Debug, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let protocol_state = value.protocol_state;

        let crate::ProtocolContractState::Running(running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        // For the soft release we give every participant a mocked attestation.
        // Since this upgrade has a non-backwards compatible change, instead of manually mapping the attestations
        // we give everyone a new mock attestation again instead.
        // clear previous attestations from the storage trie
        let stale_participant_attestations = value.tee_state.participants_attestations;
        let threshold_parameters = &running_state.parameters.participants();
        let tee_state = crate::TeeState::with_mocked_participant_attestations(threshold_parameters);

        Self {
            protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            proposed_updates: value.proposed_updates,
            config: value.config,
            tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {
                participant_attestations: Some(stale_participant_attestations),
            },
        }
    }
}
