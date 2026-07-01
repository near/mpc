//! ## Overview
//! Shadows the contract state written by the `3.13.0` release so [`crate::migrate`]
//! can upgrade from it. See [`crate::v3_12_0_state`] for the rationale and guideline.
//!
//! `3.13.0` differs from the live layout only by the two fields this version adds:
//! `Config::fail_attestation_submission_tera_gas` (and the three verifier gas knobs,
//! all defaulted here) and the `MpcContract::pending_attestations` map.

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
        domain::max_reconstruction_threshold,
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
    },
    state::{ProtocolContractState, running::RunningContractState},
    storage_keys::StorageKey,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};

/// The `Config` layout written by the `3.13.0` contract, before
/// `fail_attestation_submission_tera_gas` and the verifier gas knobs were added.
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
            // New in this version: the attestation fail-call and verifier-call gas
            // knobs, added alongside the async attestation flow.
            ..crate::Config::default()
        }
    }
}

/// Keep this module in sync with [`crate::MpcContract`]: it is the `3.13.0` layout,
/// which differs only by the appended `pending_attestations` map.
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

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if let ProtocolContractState::Running(running) = &old.protocol_state {
            validate_threshold_relation_on_migration(running);
        }

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config.into(),
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            metrics: old.metrics,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            pending_attestations: LookupMap::new(StorageKey::PendingAttestations),
        }
    }
}

fn validate_threshold_relation_on_migration(running: &RunningContractState) {
    let num_participants = running.parameters.participants().len() as u64;
    let max_reconstruction_threshold = max_reconstruction_threshold(running.domains.domains());
    if let Err(err) = ThresholdParameters::validate_governance_against_reconstruction(
        num_participants,
        running.parameters.threshold(),
        max_reconstruction_threshold,
    ) {
        env::panic_str(&format!(
            "Migration aborted: existing state violates the GovernanceThreshold/ReconstructionThreshold relation ({err:?}). num_participants={}, governance_threshold={}, max_reconstruction_threshold={:?}. Correct it via vote_new_parameters before upgrading.",
            num_participants,
            running.parameters.threshold().value(),
            max_reconstruction_threshold.map(|t| t.inner()),
        ));
    }
}
