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
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};

/// Shadow of the `3.13.0` [`Config`]: the deployed layout predates the async
/// attestation gas fields (`fail_attestation_submission_tera_gas`,
/// `verifier_tera_gas`, `resolve_verification_tera_gas`), so migrating state
/// written by `3.13.0` must deserialize the old field set and then default the
/// new ones.
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
        // Carry the deployed values; the async attestation gas fields are new in
        // this release, so take their defaults.
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
    tee_state: TeeState,
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
/// [`mpc_attestation::attestation::MockAttestation::with_expiry`] rewrites them as
/// expiring mocks so the normal cleanup flow can remove stale entries once the
/// window elapses. An entry whose expiry is longer than (or missing) the default
/// window is capped at it; a shorter existing expiry is left as-is.
///
/// This is a one-time upgrade step; it is removed together with this module when
/// the pre-expiry migration is retired.
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
            let stamped = mock.clone().with_expiry(expiry_timestamp_seconds);
            node_attestation.verified_attestation = VerifiedAttestation::Mock(stamped);
        }
    }
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        // Legacy `MockAttestation::Valid` entries never expire and can never be
        // cleaned up. Stamp an expiry on them so the standard cleanup flow can
        // evict stale mock entries after the upgrade.
        let mut tee_state = old.tee_state;
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
    use super::{TeeState, VerifiedAttestation, attestation, stamp_expiry_on_legacy_mocks};
    use crate::primitives::test_utils::bogus_ed25519_public_key;
    use crate::tee::tee_state::{NodeAttestation, NodeId};
    use crate::tee::test_utils::set_block_timestamp;
    use mpc_attestation::attestation::MockAttestation;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::time::Duration;

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
}
