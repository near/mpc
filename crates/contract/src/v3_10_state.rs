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
use std::collections::BTreeMap;

use crate::{
    Config, SupportedForeignChainsByNode,
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
};

/// In-flight requests inherited from the schema before the duplicate-request fan-out
/// upgrade. Kept inlined here (rather than imported) so storage written by the 3.10
/// contract still deserializes during migration. Dropped in the `From` impl below
/// because the legacy window has closed.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct LegacyPendingRequests {
    signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, YieldIndex>,
}

/// `3.10.0`'s `MpcContract` layout. Identical to the current `MpcContract` except the
/// trailing `foreign_chain_rpc_whitelist` field uses the pre-reshape type below.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    legacy_pending_requests: LegacyPendingRequests,
    metrics: dtos::Metrics,
    foreign_chain_rpc_whitelist: OldForeignChainRpcWhitelist,
}

/// `3.10.0`'s whitelist field shape: a single nested `BTreeMap`, no vote storage. The
/// `From` impl above discards it and default-initializes the current whitelist because
/// `3.10.0` had no vote endpoint and so the map is guaranteed empty.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldForeignChainRpcWhitelist {
    entries: BTreeMap<dtos::ForeignChain, BTreeMap<dtos::ProviderId, OldProviderEntry>>,
}

/// Local shadow of `3.10.0`'s `ProviderEntry` borsh shape. The current revision renamed
/// the public DTO to `ProviderConfig` and dropped the `provider_id` field (it became the
/// map key), so the public DTO no longer matches `3.10.0`'s on-disk bytes. `3.10.0`
/// guarantees the outer map is empty, so this inner type is never actually deserialized
/// — but the parent `BTreeMap<ProviderId, _>` still needs a concrete `V: BorshDeserialize`
/// to satisfy the type bound on the derive.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldProviderEntry {
    provider_id: dtos::ProviderId,
    base_url: String,
    auth_scheme: dtos::AuthScheme,
    chain_routing: dtos::ChainRouting,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        // `3.10.0` had no vote endpoint, so `old.foreign_chain_rpc_whitelist.entries`
        // is guaranteed empty. Drop it and default-initialize the current reshaped
        // whitelist (empty `entries`, empty `votes.pending`).
        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config,
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            metrics: old.metrics,
            foreign_chain_rpc_whitelist: Default::default(),
        }
    }
}
