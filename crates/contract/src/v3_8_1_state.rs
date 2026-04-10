//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_sdk::store::IterableMap;
use near_sdk::store::LookupMap;

use crate::{
    node_migrations::{BackupServiceInfo, DestinationNodeInfo},
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StaleData,
};

/// Snapshot of `NodeMigrations` before `backup_service_tee_state` was added.
/// Only the fields that existed in v3.8.1 are listed here.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeMigrations {
    backup_services_info: IterableMap<AccountId, BackupServiceInfo>,
    ongoing_migrations: IterableMap<AccountId, DestinationNodeInfo>,
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
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: OldNodeMigrations,
    stale_data: StaleData,
    metrics: dtos::Metrics,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        use crate::tee::measurements::ContractExpectedMeasurements;

        // Seed backup service TeeState with default measurements (same as MPC nodes)
        let backup_service_tee_state = {
            let mut state = TeeState::default();
            for m in mpc_attestation::attestation::default_measurements() {
                state.allowed_measurements.add(ContractExpectedMeasurements::from(m.clone()));
            }
            state
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
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: crate::node_migrations::NodeMigrations::from_old(
                value.node_migrations.backup_services_info,
                value.node_migrations.ongoing_migrations,
                backup_service_tee_state,
            ),
            stale_data: value.stale_data,
            metrics: value.metrics,
        }
    }
}
