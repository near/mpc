//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{self as dtos, VerifyForeignTransactionRequest};
use near_sdk::{env, store::LookupMap};

use crate::{
    foreign_chain_rpc::ForeignChainRpcWhitelist,
    node_migrations::NodeMigrations,
    pending_requests::LegacyPendingRequests,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, SupportedForeignChainsByNode,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    legacy_pending_requests: LegacyPendingRequests,
    metrics: dtos::Metrics,
    foreign_chain_rpc_whitelist: ForeignChainRpcWhitelist,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        if !matches!(value.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            node_foreign_chain_support: value.node_foreign_chain_support,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            // TODO(#3279): drop `legacy_pending_requests` from `crate::MpcContract` and
            // stop carrying it across migration.
            legacy_pending_requests: value.legacy_pending_requests,
            metrics: value.metrics,
            foreign_chain_rpc_whitelist: value.foreign_chain_rpc_whitelist,
        }
    }
}
