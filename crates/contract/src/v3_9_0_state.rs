//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::BTreeMap;

use assert_matches::assert_matches;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::hash::NodeImageHash;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{near, store::LookupMap};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        key_state::AuthenticatedParticipantId,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::{
        measurements::{AllowedMeasurements, MeasurementVoteAction, MeasurementVotes},
        proposal::{
            AllowedDockerImageHashes, AllowedLauncherImages, CodeHashesVotes, LauncherHashVotes,
            LauncherVoteAction,
        },
        tee_state::NodeAttestation,
    },
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, NodeForeignChainConfigurations,
};

/// Previous `StaleData` layout — held a [`LookupMap`] of pre-upgrade signature requests.
/// After the v3.9 migration is fully deployed those requests have been resolved or timed
/// out, so the field is dropped here and the new `StaleData` is empty.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldStaleData {
    pending_signature_requests_pre_upgrade: LookupMap<SignatureRequest, YieldIndex>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldLauncherHashVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, LauncherVoteAction>,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OldMeasurementVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, MeasurementVoteAction>,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OldCodeHashesVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, NodeImageHash>,
}

/// Previous TeeState layout — without `allowed_measurements` and `measurement_votes` fields.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: AllowedDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: OldCodeHashesVotes,
    launcher_votes: OldLauncherHashVotes,
    stored_attestations: BTreeMap<near_sdk::PublicKey, NodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: OldMeasurementVotes,
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
    node_foreign_chain_configurations: NodeForeignChainConfigurations,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: OldStaleData,
    metrics: dtos::Metrics,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        assert_matches!(
            &value.protocol_state,
            crate::ProtocolContractState::Running(_)
        );

        let mut new_launcher_votes = LauncherHashVotes::new(
            StorageKey::LauncherHashVotesByVoter,
            StorageKey::LauncherHashVotesByProposal,
        );
        for (authenticated_id, launcher_vote) in value.tee_state.launcher_votes.vote_by_account {
            new_launcher_votes.vote(authenticated_id, launcher_vote.into());
        }

        let mut new_measurement_votes = MeasurementVotes::new(
            StorageKey::MeasurementVotesByVoter,
            StorageKey::MeasurementVotesByProposal,
        );
        for (authenticated_id, measurement_vote) in
            value.tee_state.measurement_votes.vote_by_account
        {
            new_measurement_votes.vote(authenticated_id, measurement_vote.into());
        }

        let mut new_code_hash_votes = CodeHashesVotes::new(
            StorageKey::CodeHashVotesByVoter,
            StorageKey::CodeHashVotesByProposal,
        );
        for (authenticated_id, code_hash_vote) in value.tee_state.votes.proposal_by_account {
            new_code_hash_votes.vote(authenticated_id, code_hash_vote.into());
        }

        let new_tee_state = crate::tee::tee_state::TeeState {
            allowed_docker_image_hashes: value.tee_state.allowed_docker_image_hashes,
            allowed_launcher_images: value.tee_state.allowed_launcher_images,
            votes: new_code_hash_votes,
            launcher_votes: new_launcher_votes,
            stored_attestations: value.tee_state.stored_attestations,
            allowed_measurements: value.tee_state.allowed_measurements,
            measurement_votes: new_measurement_votes,
        };

        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy: value.foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            node_foreign_chain_configurations: value.node_foreign_chain_configurations,
            config: value.config,
            tee_state: new_tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {},
            metrics: value.metrics,
        }
    }
}
