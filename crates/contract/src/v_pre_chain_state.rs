//! Pre-upgrade `MpcContract` snapshot, captured immediately before the
//! `ChainState` field was added.
//!
//! Only the borsh layout of `MpcContract` itself changed — every transitively
//! referenced struct retains its previous shape — so we just reuse the current
//! crate types and re-declare the contract struct with the field ordering
//! that was on-chain prior to this upgrade. The `From` impl initializes
//! `chain_state` to an empty `ChainState`; in-flight pending requests at
//! upgrade time keep working as length-1 chains.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types as dtos;
use near_sdk::store::LookupMap;

use crate::{
    node_migrations::NodeMigrations,
    pending_requests::ChainState,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, Metrics, StaleData, SupportedForeignChainsByNode,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
    metrics: Metrics,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            chain_state: ChainState::new(),
            proposed_updates: value.proposed_updates,
            node_foreign_chain_support: value.node_foreign_chain_support,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: value.stale_data,
            metrics: value.metrics,
        }
    }
}
