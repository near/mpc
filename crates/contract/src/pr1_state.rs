//! State-migration shim from PR 1 (#3216, `feat: implement foreign chain RPC providers
//! in contract`) to PR 2 (this PR).
//!
//! PR 1 shipped `ForeignChainRpcWhitelist { entries: BTreeMap<ForeignChain, BTreeMap<ProviderId, ProviderEntry>> }`
//! with no vote endpoint, so the whitelist is guaranteed empty in any PR-1-only
//! deployment. PR 2 reshapes that field to `{ entries: BTreeMap<ForeignChain, ChainEntry>,
//! votes: ProviderVotes }`. The two layouts are borsh-incompatible (different field
//! count + different inner map shape), so this module reads the old shape and converts.
//!
//! Reachable only if PR 1's binary lands in some environment ahead of PR 2. If the
//! team ships PR 1's main snapshot and PR 2's together, the legacy → PR 2 path via
//! `v3_9_1_state` handles everything and this code is unused. Kept as a guard.

use borsh::BorshDeserialize;
use near_mpc_contract_interface::types as dtos;
use near_sdk::store::LookupMap;
use std::collections::BTreeMap;

use crate::{
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

/// PR 1's `MpcContract` layout. Identical to current `MpcContract` except the
/// trailing `foreign_chain_rpc_whitelist` field uses the pre-reshape type below.
//
// Fields are read by `From<MpcContract>` even though rustc can't see that
// (the derive-generated `deserialize_reader` writes them, the conversion reads them);
// silence the warning.
#[expect(
    dead_code,
    reason = "fields consumed by From<MpcContract> conversion below"
)]
#[derive(BorshDeserialize)]
pub struct MpcContract {
    pub(crate) protocol_state: ProtocolContractState,
    pub(crate) pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pub(crate) pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pub(crate) pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    pub(crate) proposed_updates: ProposedUpdates,
    pub(crate) node_foreign_chain_support: SupportedForeignChainsByNode,
    pub(crate) config: Config,
    pub(crate) tee_state: TeeState,
    pub(crate) accept_requests: bool,
    pub(crate) node_migrations: NodeMigrations,
    pub(crate) legacy_pending_requests: LegacyPendingRequests,
    pub(crate) metrics: dtos::Metrics,
    pub(crate) foreign_chain_rpc_whitelist: ForeignChainRpcWhitelistPr1,
}

/// PR 1's whitelist field shape: a single nested `BTreeMap`, no vote storage.
#[expect(
    dead_code,
    reason = "field consumed by the parent borsh-deserialize then discarded — PR 1 guarantees the map is empty"
)]
#[derive(BorshDeserialize)]
pub struct ForeignChainRpcWhitelistPr1 {
    pub(crate) entries:
        BTreeMap<dtos::ForeignChain, BTreeMap<dtos::ProviderId, dtos::ProviderEntry>>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        // PR 1 had no vote endpoint, so `old.foreign_chain_rpc_whitelist.entries` is
        // guaranteed empty. Drop it and default-initialize PR 2's reshaped whitelist
        // (empty `entries`, empty `votes.pending`).
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
            legacy_pending_requests: old.legacy_pending_requests,
            metrics: old.metrics,
            foreign_chain_rpc_whitelist: Default::default(),
        }
    }
}
