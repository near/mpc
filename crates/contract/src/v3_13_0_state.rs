//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.
//!
//! Relative to `3.13.0`, this release adds two `Config` fields
//! (`launcher_hash_unused_ttl_seconds`, `clean_expired_launcher_hashes_tera_gas`) and a
//! `last_used` timestamp to each `AllowedLauncherImage`. Those are the only borsh-layout
//! changes, so only `Config` and `TeeState` are shadowed here; every other field reuses the
//! real (byte-identical) type.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{Metrics, VerifyForeignTransactionRequest};
use near_sdk::{
    AccountId, env,
    store::{Lazy, LookupMap},
};

use crate::{
    SupportedForeignChainsByNode,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::verifier_votes::TeeVerifierVotes,
    update::ProposedUpdates,
};

/// The `Config` layout written by the `3.13.0` contract, before
/// `launcher_hash_unused_ttl_seconds` and `clean_expired_launcher_hashes_tera_gas` were
/// appended.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldConfig {
    key_event_timeout_blocks: u64,
    tee_upgrade_deadline_duration_seconds: u64,
    contract_upgrade_deposit_tera_gas: u64,
    sign_call_gas_attachment_requirement_tera_gas: u64,
    ckd_call_gas_attachment_requirement_tera_gas: u64,
    return_signature_and_clean_state_on_success_call_tera_gas: u64,
    return_ck_and_clean_state_on_success_call_tera_gas: u64,
    fail_on_timeout_tera_gas: u64,
    clean_tee_status_tera_gas: u64,
    clean_invalid_attestations_tera_gas: u64,
    cleanup_orphaned_node_migrations_tera_gas: u64,
    remove_non_participant_update_votes_tera_gas: u64,
    clean_foreign_chain_data_tera_gas: u64,
    remove_non_participant_tee_verifier_votes_tera_gas: u64,
}

impl From<OldConfig> for crate::Config {
    fn from(old: OldConfig) -> Self {
        crate::Config {
            key_event_timeout_blocks: old.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: old.tee_upgrade_deadline_duration_seconds,
            contract_upgrade_deposit_tera_gas: old.contract_upgrade_deposit_tera_gas,
            sign_call_gas_attachment_requirement_tera_gas: old
                .sign_call_gas_attachment_requirement_tera_gas,
            ckd_call_gas_attachment_requirement_tera_gas: old
                .ckd_call_gas_attachment_requirement_tera_gas,
            return_signature_and_clean_state_on_success_call_tera_gas: old
                .return_signature_and_clean_state_on_success_call_tera_gas,
            return_ck_and_clean_state_on_success_call_tera_gas: old
                .return_ck_and_clean_state_on_success_call_tera_gas,
            fail_on_timeout_tera_gas: old.fail_on_timeout_tera_gas,
            clean_tee_status_tera_gas: old.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: old.clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: old
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: old
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: old.clean_foreign_chain_data_tera_gas,
            remove_non_participant_tee_verifier_votes_tera_gas: old
                .remove_non_participant_tee_verifier_votes_tera_gas,
            // New in this version: default the launcher-eviction TTL and its cleanup gas.
            ..crate::Config::default()
        }
    }
}

/// `3.13.0` layout of `AllowedLauncherImage`: the current type appends a `last_used`
/// timestamp, so the real type can no longer decode old bytes.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldAllowedLauncherImage {
    launcher_hash: mpc_primitives::hash::LauncherImageHash,
    compose_hashes: Vec<mpc_primitives::hash::LauncherDockerComposeHash>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldAllowedLauncherImages {
    entries: Vec<OldAllowedLauncherImage>,
}

/// `3.13.0` layout of `TeeState`. Only `allowed_launcher_images` changed borsh
/// layout; every other field reuses the real (byte-identical) type. Field order
/// must match [`crate::tee::tee_state::TeeState`] exactly.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: crate::tee::proposal::StoredDockerImageHashes,
    allowed_launcher_images: OldAllowedLauncherImages,
    votes: crate::tee::proposal::CodeHashesVotes,
    launcher_votes: crate::tee::proposal::LauncherHashVotes,
    stored_attestations: near_sdk::store::IterableMap<
        near_mpc_contract_interface::types::Ed25519PublicKey,
        crate::tee::tee_state::NodeAttestation,
    >,
    allowed_measurements: crate::tee::measurements::AllowedMeasurements,
    measurement_votes: crate::tee::measurements::MeasurementVotes,
}

impl From<OldTeeState> for crate::tee::tee_state::TeeState {
    fn from(old: OldTeeState) -> Self {
        // `new` stamps `last_used` to the migration block time (constant within this call).
        let entries = old
            .allowed_launcher_images
            .entries
            .into_iter()
            .map(|e| {
                crate::tee::proposal::AllowedLauncherImage::new(e.launcher_hash, e.compose_hashes)
            })
            .collect();
        crate::tee::tee_state::TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: crate::tee::proposal::AllowedLauncherImages::from_entries(
                entries,
            ),
            votes: old.votes,
            launcher_votes: old.launcher_votes,
            stored_attestations: old.stored_attestations,
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        }
    }
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.13.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: OldConfig,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    metrics: Metrics,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: Option<AccountId>,
    tee_verifier_votes: TeeVerifierVotes,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config.into(),
            tee_state: old.tee_state.into(),
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            metrics: old.metrics,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_keys::StorageKey;
    use crate::tee::proposal::{
        CodeHashesVotes, LauncherHashVotes, StoredDockerImageHashes, get_docker_compose_hash,
    };
    use mpc_primitives::hash::{LauncherImageHash, NodeImageHash};
    use near_sdk::store::IterableMap;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    /// The `3.13.0` launcher layout (no timestamp) must deserialize under the shadow and
    /// migrate: launcher hash + compose hashes preserved, and `last_used` set to the
    /// migration time (NOT the borsh/epoch default, which would immediately expire every
    /// migrated hash). Two entries + a short TTL defeat the newest-only read fallback, so
    /// both surviving proves the timestamp was stamped to "now".
    #[test]
    fn migrating_launcher_images_preserves_hashes_and_stamps_timestamps() {
        const MIGRATION_TIME_SECS: u64 = 1_000_000;
        let launcher_1 = LauncherImageHash::from([1u8; 32]);
        let launcher_2 = LauncherImageHash::from([2u8; 32]);
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let compose_1 = get_docker_compose_hash(&launcher_1, &mpc_hash);
        let compose_2 = get_docker_compose_hash(&launcher_2, &mpc_hash);

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(MIGRATION_TIME_SECS * 1_000_000_000)
                .build()
        );

        let old = OldTeeState {
            allowed_docker_image_hashes: StoredDockerImageHashes::default(),
            allowed_launcher_images: OldAllowedLauncherImages {
                entries: vec![
                    OldAllowedLauncherImage {
                        launcher_hash: launcher_1,
                        compose_hashes: vec![compose_1],
                    },
                    OldAllowedLauncherImage {
                        launcher_hash: launcher_2,
                        compose_hashes: vec![compose_2],
                    },
                ],
            },
            votes: CodeHashesVotes::default(),
            launcher_votes: LauncherHashVotes::default(),
            stored_attestations: IterableMap::new(StorageKey::StoredAttestations),
            allowed_measurements: Default::default(),
            measurement_votes: Default::default(),
        };

        // Round-trip through borsh to exercise the shadow's on-chain byte layout.
        let bytes = borsh::to_vec(&old).unwrap();
        let decoded: OldTeeState = borsh::from_slice(&bytes).unwrap();
        let migrated: crate::tee::tee_state::TeeState = decoded.into();

        // Launcher hashes and compose hashes are carried over.
        let big_ttl = std::time::Duration::from_secs(1_000_000_000);
        assert_eq!(
            migrated.get_allowed_launcher_hashes(big_ttl),
            vec![launcher_1, launcher_2]
        );
        assert_eq!(
            migrated.get_allowed_launcher_compose_hashes(big_ttl),
            vec![compose_1, compose_2]
        );

        // Timestamps were stamped to the migration time: under a short TTL at that same
        // (large) block time, both entries are still live. Had they defaulted to epoch 0,
        // both would be expired and the fallback would surface only one.
        let short_ttl = std::time::Duration::from_secs(100);
        assert_eq!(migrated.get_allowed_launcher_hashes(short_ttl).len(), 2);
    }
}
