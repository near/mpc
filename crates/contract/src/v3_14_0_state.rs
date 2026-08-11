//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::VerifyForeignTransactionRequest;
use near_sdk::{
    AccountId, env,
    store::{IterableMap, Lazy, LookupMap},
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
    storage_keys::StorageKey,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};

/// Shadow of the `3.14.0` [`Config`]: the deployed layout predates this release's
/// `attestation_storage_fee_millinear`, so migrating `3.14.0` state deserializes the old
/// field set and defaults the new one.
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
    fail_attestation_submission_tera_gas: u64,
    clean_tee_status_tera_gas: u64,
    clean_invalid_attestations_tera_gas: u64,
    cleanup_orphaned_node_migrations_tera_gas: u64,
    remove_non_participant_update_votes_tera_gas: u64,
    clean_foreign_chain_data_tera_gas: u64,
    remove_non_participant_tee_verifier_votes_tera_gas: u64,
    verifier_tera_gas: u64,
    resolve_verification_tera_gas: u64,
    launcher_hash_unused_ttl_seconds: u64,
}

impl From<OldConfig> for Config {
    fn from(old: OldConfig) -> Self {
        // Carry the deployed values; the attestation-storage fee is new in this release, so
        // it takes its default.
        //
        // `clean_invalid_attestations_tera_gas` is the deliberate exception: it is reset to
        // the new default rather than carried over. The deployed 10 TGas cannot fund the scan
        // `vote_reshared` requests, and the promise is detached, so every removal rolls back
        // unnoticed. Carrying it forward would leave the fix unreachable without a
        // governance config vote.
        //
        // TODO(#4121): one-shot for this upgrade only. These modules are seeded by copying
        // the previous release's, and carried forward this line would clobber an
        // operator-voted value on every future upgrade.
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
            fail_attestation_submission_tera_gas: old.fail_attestation_submission_tera_gas,
            clean_tee_status_tera_gas: old.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: Config::default()
                .clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: old
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: old
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: old.clean_foreign_chain_data_tera_gas,
            remove_non_participant_tee_verifier_votes_tera_gas: old
                .remove_non_participant_tee_verifier_votes_tera_gas,
            verifier_tera_gas: old.verifier_tera_gas,
            resolve_verification_tera_gas: old.resolve_verification_tera_gas,
            launcher_hash_unused_ttl_seconds: old.launcher_hash_unused_ttl_seconds,
            ..Default::default()
        }
    }
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.14.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    /// The deployed `3.14.0` keys predate `expected_payload_hash`, so this type parameter
    /// does not describe their borsh layout — do not read entries through this map. Not
    /// shadowed because `LookupMap`'s own borsh form is just the storage prefix: the type
    /// parameters never touch the state deserialization this struct exists for, and the
    /// migration discards the map unread.
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: OldConfig,
    tee_state: TeeState,
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
            // `VerifyForeignTransactionRequest` gained `expected_payload_hash`, changing the
            // borsh key encoding, so entries pending at upgrade time are abandoned; their
            // yielded promises time out on chain as if never responded to. The abandoned V2 entries
            // are no longer addressable, so their storage staking is never reclaimed
            // (bounded by the number of requests in flight at upgrade time).
            pending_verify_foreign_tx_requests: LookupMap::new(
                crate::storage_keys::StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config.into(),
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        }
    }
}

/// Unused signature counters, dropped by the migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct Metrics {
    sign_with_v1_payload_count: u64,
    sign_with_v2_payload_count: u64,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    /// Every field distinguishable from [`Config::default()`], so a carried-forward value
    /// cannot be mistaken for a defaulted one.
    fn deployed_config() -> OldConfig {
        OldConfig {
            key_event_timeout_blocks: 1,
            tee_upgrade_deadline_duration_seconds: 2,
            contract_upgrade_deposit_tera_gas: 3,
            sign_call_gas_attachment_requirement_tera_gas: 4,
            ckd_call_gas_attachment_requirement_tera_gas: 5,
            return_signature_and_clean_state_on_success_call_tera_gas: 6,
            return_ck_and_clean_state_on_success_call_tera_gas: 7,
            fail_on_timeout_tera_gas: 8,
            fail_attestation_submission_tera_gas: 9,
            clean_tee_status_tera_gas: 10,
            clean_invalid_attestations_tera_gas: 11,
            cleanup_orphaned_node_migrations_tera_gas: 12,
            remove_non_participant_update_votes_tera_gas: 13,
            clean_foreign_chain_data_tera_gas: 14,
            remove_non_participant_tee_verifier_votes_tera_gas: 15,
            verifier_tera_gas: 16,
            resolve_verification_tera_gas: 17,
            launcher_hash_unused_ttl_seconds: 18,
        }
    }

    /// The deployed budget cannot fund the scan [`crate::MpcContract::vote_reshared`] requests,
    /// and the promise is detached, so the sweep rolls back silently. Migration resets this one
    /// field so the fix lands on upgrade rather than needing a governance vote.
    #[test]
    fn config_migration__should_reset_clean_invalid_attestations_gas_to_the_new_default() {
        // given
        let old = deployed_config();
        assert_ne!(
            old.clean_invalid_attestations_tera_gas,
            Config::default().clean_invalid_attestations_tera_gas
        );

        // when
        let migrated = Config::from(old);

        // then
        assert_eq!(
            migrated.clean_invalid_attestations_tera_gas,
            Config::default().clean_invalid_attestations_tera_gas
        );
    }

    /// The reset must not leak into any other field an operator may have voted in.
    ///
    /// Compares the whole struct rather than field by field, so adding a field to [`Config`]
    /// fails to compile here until this test says whether it carries forward or defaults.
    #[test]
    fn config_migration__should_carry_every_other_deployed_value_forward() {
        // given
        let old = deployed_config();

        // when
        let migrated = Config::from(deployed_config());

        // then
        assert_eq!(
            migrated,
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
                fail_attestation_submission_tera_gas: old.fail_attestation_submission_tera_gas,
                clean_tee_status_tera_gas: old.clean_tee_status_tera_gas,
                cleanup_orphaned_node_migrations_tera_gas: old
                    .cleanup_orphaned_node_migrations_tera_gas,
                remove_non_participant_update_votes_tera_gas: old
                    .remove_non_participant_update_votes_tera_gas,
                clean_foreign_chain_data_tera_gas: old.clean_foreign_chain_data_tera_gas,
                remove_non_participant_tee_verifier_votes_tera_gas: old
                    .remove_non_participant_tee_verifier_votes_tera_gas,
                verifier_tera_gas: old.verifier_tera_gas,
                resolve_verification_tera_gas: old.resolve_verification_tera_gas,
                launcher_hash_unused_ttl_seconds: old.launcher_hash_unused_ttl_seconds,
                // Reset, not carried; covered by the test above.
                clean_invalid_attestations_tera_gas: Config::default()
                    .clean_invalid_attestations_tera_gas,
                // New in this release, so it takes its default.
                attestation_storage_fee_millinear: Config::default()
                    .attestation_storage_fee_millinear,
            }
        );
    }
}
