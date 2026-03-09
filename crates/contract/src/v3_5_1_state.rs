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
use contract_interface::types as dtos;
use mpc_attestation::attestation::VerifiedAttestation;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, store::LookupMap};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::{
        proposal::{
            AllowedDockerImageHashes, AllowedLauncherImage, AllowedLauncherImages,
            AllowedMpcDockerImage, CodeHashesVotes, LauncherHashVotes,
        },
        tee_state::NodeId,
    },
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StaleData,
};

/// The hardcoded launcher image hash from the previous template.
/// Used during migration to associate existing compose hashes with their launcher image.
const LEGACY_LAUNCHER_IMAGE_HASH: &str =
    "e28cb0425db06255fe5fc7aadb79534ac63c94c7a721f75c1af1e934d2eb0701";

/// Previous NodeAttestation layout — identical structure, just needs re-declaration
/// for the old TeeState deserialization.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: NodeId,
    verified_attestation: VerifiedAttestation,
}

/// Previous AllowedMpcDockerImage layout — contained a docker_compose_hash field.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct OldAllowedMpcDockerImage {
    image_hash: mpc_primitives::hash::MpcDockerImageHash,
    docker_compose_hash: LauncherDockerComposeHash,
    added: crate::primitives::time::Timestamp,
}

/// Previous AllowedDockerImageHashes layout.
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct OldAllowedDockerImageHashes {
    allowed_tee_proposals: Vec<OldAllowedMpcDockerImage>,
}

/// Previous TeeState with old AllowedDockerImageHashes format.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeStateWithOldImageHashes {
    allowed_docker_image_hashes: OldAllowedDockerImageHashes,
    allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    votes: CodeHashesVotes,
    stored_attestations: BTreeMap<near_sdk::PublicKey, OldNodeAttestation>,
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
    tee_state: OldTeeStateWithOldImageHashes,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
    metrics: dtos::Metrics,
}

fn migrate_launcher_compose_hashes(
    old_compose_hashes: Vec<LauncherDockerComposeHash>,
) -> AllowedLauncherImages {
    if old_compose_hashes.is_empty() {
        return AllowedLauncherImages::default();
    }

    // Parse the legacy launcher image hash
    let launcher_hash_bytes: [u8; 32] = hex::decode(LEGACY_LAUNCHER_IMAGE_HASH)
        .expect("LEGACY_LAUNCHER_IMAGE_HASH must be valid hex")
        .try_into()
        .expect("LEGACY_LAUNCHER_IMAGE_HASH must be 32 bytes");

    let launcher_hash = mpc_primitives::hash::LauncherImageHash::from(launcher_hash_bytes);

    let entry = AllowedLauncherImage {
        launcher_hash,
        compose_hashes: old_compose_hashes,
    };

    AllowedLauncherImages::from_entries(vec![entry])
}

fn migrate_allowed_docker_image_hashes(
    old: OldAllowedDockerImageHashes,
) -> AllowedDockerImageHashes {
    let new_proposals: Vec<AllowedMpcDockerImage> = old
        .allowed_tee_proposals
        .into_iter()
        .map(|old_entry| AllowedMpcDockerImage {
            image_hash: old_entry.image_hash,
            added: old_entry.added,
        })
        .collect();

    AllowedDockerImageHashes::from_proposals(new_proposals)
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let crate::ProtocolContractState::Running(_running_state) = &value.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        let allowed_launcher_images =
            migrate_launcher_compose_hashes(value.tee_state.allowed_launcher_compose_hashes);
        let allowed_docker_image_hashes =
            migrate_allowed_docker_image_hashes(value.tee_state.allowed_docker_image_hashes);

        // Convert stored attestations (same structure, just re-wrapped)
        let stored_attestations: BTreeMap<
            near_sdk::PublicKey,
            crate::tee::tee_state::NodeAttestation,
        > = value
            .tee_state
            .stored_attestations
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    crate::tee::tee_state::NodeAttestation {
                        node_id: v.node_id,
                        verified_attestation: v.verified_attestation,
                    },
                )
            })
            .collect();

        let new_tee_state = crate::tee::tee_state::TeeState {
            allowed_docker_image_hashes,
            allowed_launcher_images,
            votes: value.tee_state.votes,
            launcher_votes: LauncherHashVotes::default(),
            stored_attestations,
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
