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
//! (`launcher_hash_unused_ttl_seconds`, `clean_expired_launcher_hashes_tera_gas`) and an
//! `expires_at` timestamp to each `AllowedLauncherImage`. Those are the only borsh-layout
//! changes, so only `Config` and `TeeState` are shadowed here; every other field reuses the
//! real (byte-identical) type.

use std::time::Duration;

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{Metrics, VerifyForeignTransactionRequest};
use near_sdk::{
    AccountId, env,
    store::{Lazy, LookupMap},
};

use crate::{
    SupportedForeignChainsByNode,
    config::Config,
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

/// Shadow of the `3.13.0` [`Config`]: the deployed layout predates this release's new
/// `Config` fields — the async attestation gas fields (`fail_attestation_submission_tera_gas`,
/// `verifier_tera_gas`, `resolve_verification_tera_gas`) and the launcher-eviction fields
/// (`launcher_hash_unused_ttl_seconds`, `clean_expired_launcher_hashes_tera_gas`) — so
/// migrating `3.13.0` state deserializes the old field set and defaults the new ones.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldConfig {
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

impl From<OldConfig> for Config {
    fn from(old: OldConfig) -> Self {
        // Carry the deployed values; the new fields (async attestation gas + launcher
        // eviction) are added in this release, so take their defaults.
        Config {
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
            ..Config::default()
        }
    }
}

/// `3.13.0` layout of `AllowedLauncherImage`: the current type appends an `expires_at`
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

impl OldTeeState {
    /// Migrated launcher entries get `expires_at = migration time + launcher_unused_ttl`, so
    /// every existing hash starts a fresh TTL window. Deriving the deadline here (rather than
    /// letting reads apply the TTL) is why this needs the config value — hence a method
    /// instead of a `From` impl.
    fn migrate(self, launcher_unused_ttl: Duration) -> crate::tee::tee_state::TeeState {
        let entries = self
            .allowed_launcher_images
            .entries
            .into_iter()
            .map(|e| {
                crate::tee::proposal::AllowedLauncherImage::new(
                    e.launcher_hash,
                    e.compose_hashes,
                    launcher_unused_ttl,
                )
            })
            .collect();
        crate::tee::tee_state::TeeState {
            allowed_docker_image_hashes: self.allowed_docker_image_hashes,
            allowed_launcher_images: crate::tee::proposal::AllowedLauncherImages::from_entries(
                entries,
            ),
            votes: self.votes,
            launcher_votes: self.launcher_votes,
            stored_attestations: self.stored_attestations,
            allowed_measurements: self.allowed_measurements,
            measurement_votes: self.measurement_votes,
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

        // The launcher expiry stamped below is derived from the migrated config's TTL, so the
        // config must be converted first.
        let config: Config = old.config.into();
        let launcher_unused_ttl = Duration::from_secs(config.launcher_hash_unused_ttl_seconds);

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            tee_state: old.tee_state.migrate(launcher_unused_ttl),
            config,
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
#[expect(non_snake_case)]
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
    /// migrate: launcher hash + compose hashes preserved, and `expires_at` set to
    /// `migration time + TTL` (NOT the borsh/epoch default, which would immediately expire
    /// every migrated hash). Two entries defeat the read fallback, so both surviving proves
    /// the deadline was stamped forward.
    #[test]
    fn migrate__should_preserve_launcher_hashes_and_stamp_deadlines_forward() {
        const MIGRATION_TIME_SECS: u64 = 1_000_000;
        const TTL: Duration = Duration::from_secs(100);
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
        let migrated = decoded.migrate(TTL);

        // Both entries survive at the migration instant, so the deadlines were stamped
        // forward rather than defaulting to the epoch.
        assert_eq!(
            migrated.get_allowed_launcher_hashes(),
            vec![launcher_1, launcher_2]
        );
        assert_eq!(
            migrated.get_allowed_launcher_compose_hashes(),
            vec![compose_1, compose_2]
        );
        assert_eq!(
            migrated
                .allowed_launcher_images
                .expires_at_secs(&launcher_1),
            Some(MIGRATION_TIME_SECS + TTL.as_secs())
        );
    }
}
