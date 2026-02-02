//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::Attestation;
use near_sdk::{
    env,
    store::{IterableMap, LookupMap},
};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::{NodeId, TeeState},
    update::ProposedUpdates,
    Config,
};

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
struct StaleData {
    /// Holds the TEE attestations from the previous contract version.
    /// This is stored as an `Option` so it can be `.take()`n during the cleanup process,
    /// ensuring the `IterableMap` handle is properly dropped.
    participant_attestations: Option<IterableMap<near_sdk::PublicKey, (NodeId, Attestation)>>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let protocol_state = value.protocol_state;

        let crate::ProtocolContractState::Running(_running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        Self {
            protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            proposed_updates: value.proposed_updates,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {},
        }
    }
}
