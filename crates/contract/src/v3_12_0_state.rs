//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{Metrics, VerifyForeignTransactionRequest};
use near_sdk::{
    env,
    store::{Lazy, LookupMap},
};

use crate::{
    SupportedForeignChainsByNode,
    foreign_chain_rpc::ForeignChainRpcWhitelist,
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

/// The `Config` layout written by the `3.12.0` contract, before
/// `remove_non_participant_tee_verifier_votes_tera_gas` was appended.
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
            // New in this version: default the gas for the verifier-vote cleanup
            // promise added after `3.12.0`.
            ..crate::Config::default()
        }
    }
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.12.0` contract still deserializes during migration.
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
    foreign_chain_rpc_whitelist: ForeignChainRpcWhitelist,
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
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata {
                    rpc_whitelist: old.foreign_chain_rpc_whitelist,
                    ..Default::default()
                },
            ),
            tee_verifier_account_id: None,
            tee_verifier_votes: TeeVerifierVotes::default(),
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
