//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::{self, VerifiedAttestation};
use near_mpc_contract_interface::types::{
    Ed25519PublicKey, Metrics, VerifyForeignTransactionRequest,
};
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
    tee::tee_state::TeeState,
    tee::verifier_votes::TeeVerifierVotes,
    update::ProposedUpdates,
};

/// Shadow of the `3.13.0` [`Config`]: the deployed layout predates this release's new
/// [`Config`] fields — the async attestation gas fields (`fail_attestation_submission_tera_gas`,
/// `verifier_tera_gas`, `resolve_verification_tera_gas`) and the launcher-eviction field
/// (`launcher_hash_unused_ttl_seconds`) — so
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

/// `3.13.0` layout of [`AllowedLauncherImage`](crate::tee::proposal::AllowedLauncherImage): the current type appends an `expires_at`
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

/// `3.13.0` layout of [`TeeState`]. Only `allowed_launcher_images` changed borsh
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
        // `new` stamps `expires_at = migration_block_time + default_TTL` (constant within
        // this call), so migrated entries stay live for the default unused-TTL window.
        let ttl =
            std::time::Duration::from_secs(crate::config::DEFAULT_LAUNCHER_HASH_UNUSED_TTL_SECONDS);
        let entries = old
            .allowed_launcher_images
            .entries
            .into_iter()
            .map(|e| {
                crate::tee::proposal::AllowedLauncherImage::new(
                    e.launcher_hash,
                    e.compose_hashes,
                    ttl,
                )
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

/// Stamps an expiry on every stored mock attestation that lacks or exceeds one —
/// both user-submitted mocks and the genesis sentinels written by
/// [`TeeState::with_mocked_participant_attestations`]. Legacy
/// [`mpc_attestation::attestation::MockAttestation::Valid`] entries pass
/// re-verification forever and can therefore never be evicted by
/// [`TeeState::clean_invalid_attestations`];
/// [`mpc_attestation::attestation::MockAttestation::with_expiry_capped_at`] rewrites them as
/// expiring mocks so the normal cleanup flow can remove stale entries once the
/// window elapses. An entry whose expiry is longer than (or missing) the default
/// window is capped at it; a shorter existing expiry is left as-is.
///
// TODO(#3978): transitional one-time upgrade step — removed together with this
// module when the pre-expiry migration is retired.
fn stamp_expiry_on_legacy_mocks(tee_state: &mut TeeState, current_timestamp_seconds: u64) {
    let expiry_timestamp_seconds =
        current_timestamp_seconds + attestation::DEFAULT_EXPIRATION_DURATION_SECONDS;

    // Collect keys before mutating to avoid iterator invalidation.
    let mock_tls_keys: Vec<Ed25519PublicKey> = tee_state
        .stored_attestations
        .iter()
        .filter(|(_, node_attestation)| {
            matches!(
                node_attestation.verified_attestation,
                VerifiedAttestation::Mock(_)
            )
        })
        .map(|(tls_pk, _)| tls_pk.clone())
        .collect();

    for tls_pk in mock_tls_keys {
        let Some(node_attestation) = tee_state.stored_attestations.get_mut(&tls_pk) else {
            continue;
        };
        if let VerifiedAttestation::Mock(mock) = &node_attestation.verified_attestation {
            let stamped = mock.clone().with_expiry_capped_at(expiry_timestamp_seconds);
            node_attestation.verified_attestation = VerifiedAttestation::Mock(stamped);
        }
    }
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        // First convert the shadowed `3.13.0` `TeeState` (stamping `expires_at` on launcher
        // entries), then stamp an expiry on legacy `MockAttestation::Valid` entries — which
        // never expire and could otherwise never be cleaned up.
        let mut tee_state: crate::tee::tee_state::TeeState = old.tee_state.into();
        stamp_expiry_on_legacy_mocks(&mut tee_state, TeeState::current_time_seconds());

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config.into(),
            tee_state,
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
    use crate::primitives::test_utils::bogus_ed25519_public_key;
    use crate::storage_keys::StorageKey;
    use crate::tee::proposal::{
        CodeHashesVotes, LauncherHashVotes, StoredDockerImageHashes, get_docker_compose_hash,
    };
    use crate::tee::tee_state::{NodeAttestation, NodeId};
    use crate::tee::test_utils::set_block_timestamp;
    use mpc_attestation::attestation::MockAttestation;
    use mpc_primitives::hash::{LauncherImageHash, NodeImageHash};
    use near_sdk::store::IterableMap;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use std::time::Duration;

    /// The `3.13.0` launcher layout (no timestamp) must deserialize under the shadow and
    /// migrate: launcher hash + compose hashes preserved, and `expires_at` set to
    /// `migration_time + default_TTL` (NOT the borsh/epoch default, which would immediately
    /// expire every migrated hash). Both entries surviving at the migration block time
    /// proves the expiry was stamped forward rather than to epoch 0.
    #[test]
    fn migration__should_preserve_launcher_hashes_and_stamp_timestamps() {
        // Given two 3.13.0 launcher entries in the old, timestamp-less layout.
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

        // When migrated (borsh round-trip through the shadow, then into the real `TeeState`).
        let bytes = borsh::to_vec(&old).unwrap();
        let decoded: OldTeeState = borsh::from_slice(&bytes).unwrap();
        let migrated: crate::tee::tee_state::TeeState = decoded.into();

        // Then launcher hashes and compose hashes are carried over.
        assert_eq!(
            migrated.get_allowed_launcher_hashes(),
            vec![launcher_1, launcher_2]
        );
        assert_eq!(
            migrated.get_allowed_launcher_compose_hashes(),
            vec![compose_1, compose_2]
        );

        // `expires_at` was stamped to `migration_time + default_TTL`: at the migration block
        // time both entries are still live (both surface, not just the newest-only fallback).
        // Had they defaulted to epoch 0, both would be expired and the fallback would surface
        // only one.
        assert_eq!(migrated.get_allowed_launcher_hashes().len(), 2);
    }

    #[test]
    fn stamp_expiry_on_legacy_mocks__should_make_valid_mock_cleanable() {
        // Given: a legacy `MockAttestation::Valid` entry stored with no expiry, as
        // written by older contract versions. Such entries pass re-verification
        // forever and cannot be cleaned up.
        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "legacy.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        tee_state.stored_attestations.insert(
            node_id.tls_public_key.clone(),
            NodeAttestation {
                node_id: node_id.clone(),
                verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
            },
        );

        // Sanity: past the default window but without migration, the un-stamped
        // entry survives cleanup indefinitely.
        set_block_timestamp((attestation::DEFAULT_EXPIRATION_DURATION_SECONDS + 1) * 1_000_000_000);
        assert_eq!(
            tee_state.clean_invalid_attestations(Duration::from_secs(0), 100),
            0
        );

        // When: the migration stamps an expiry as of block time 0 (window ends at
        // DEFAULT), which the clock (already at DEFAULT + 1) is past.
        stamp_expiry_on_legacy_mocks(&mut tee_state, 0);
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100);

        // Then: the stale legacy mock entry is removed.
        assert_eq!(removed, 1);
        assert!(
            !tee_state
                .stored_attestations
                .contains_key(&node_id.tls_public_key)
        );
    }

    #[test]
    fn migration__should_stamp_launcher_expiry_and_make_legacy_mocks_cleanable() {
        // Given: a `3.13.0` TeeState carrying both a launcher image (old, timestamp-less
        // layout) and a legacy `MockAttestation::Valid` stored attestation (no expiry) —
        // the two things this release's migration must each handle.
        const MIGRATION_TIME_SECS: u64 = 1_000_000;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(MIGRATION_TIME_SECS * 1_000_000_000)
                .build()
        );

        let launcher = LauncherImageHash::from([1u8; 32]);
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let compose = get_docker_compose_hash(&launcher, &mpc_hash);

        let mut stored_attestations = IterableMap::new(StorageKey::StoredAttestations);
        let node_id = NodeId {
            account_id: "legacy.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        stored_attestations.insert(
            node_id.tls_public_key.clone(),
            NodeAttestation {
                node_id: node_id.clone(),
                verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
            },
        );

        let old = OldTeeState {
            allowed_docker_image_hashes: StoredDockerImageHashes::default(),
            allowed_launcher_images: OldAllowedLauncherImages {
                entries: vec![OldAllowedLauncherImage {
                    launcher_hash: launcher,
                    compose_hashes: vec![compose],
                }],
            },
            votes: CodeHashesVotes::default(),
            launcher_votes: LauncherHashVotes::default(),
            stored_attestations,
            allowed_measurements: Default::default(),
            measurement_votes: Default::default(),
        };

        // When: the full `From<MpcContract>` sequence runs on the TeeState — our shadow
        // conversion (stamps launcher `expires_at`) followed by the legacy-mock stamping.
        let mut tee_state: TeeState = old.into();
        stamp_expiry_on_legacy_mocks(&mut tee_state, TeeState::current_time_seconds());

        // Then: the launcher was migrated with a stamped `expires_at` and is live.
        assert_eq!(tee_state.get_allowed_launcher_hashes(), vec![launcher]);

        // And: the previously un-expiring legacy mock is now cleanable once the clock
        // passes its stamped window — proving both migration steps applied.
        set_block_timestamp(
            (MIGRATION_TIME_SECS + attestation::DEFAULT_EXPIRATION_DURATION_SECONDS + 1)
                * 1_000_000_000,
        );
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100);
        assert_eq!(removed, 1);
        assert!(
            !tee_state
                .stored_attestations
                .contains_key(&node_id.tls_public_key)
        );
    }
}
