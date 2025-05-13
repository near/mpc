//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.
use near_account_id::AccountId;
use near_sdk::store::IterableMap;
use near_sdk::{near, store::LookupMap};
use std::collections::HashSet;

use crate::legacy_contract_state::ConfigV1;
use crate::state::ProtocolContractState;
use crate::update::UpdateId;
use crate::{config::Config, primitives::signature::{SignatureRequest, YieldIndex}, AllowedCodeHashes, MpcContract, TeeState};
use crate::primitives::code_hash::CodeHashesVotes;

#[allow(clippy::large_enum_variant)]
#[near(serializers=[borsh])]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Update {
    Config(Config),
    Contract(Vec<u8>),
    ConfigV1(ConfigV1),
}

#[near(serializers=[borsh])]
#[derive(Debug)]
struct UpdateEntry {
    updates: Vec<Update>,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct ProposedUpdates {
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MpcContractV0 {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    pub proposed_updates: ProposedUpdates,
    pub config: Config,
}

impl From<MpcContractV0> for MpcContract {
    fn from(value: MpcContractV0) -> Self {
        Self {
            protocol_state: value.protocol_state.into(),
            pending_requests: value.pending_requests,
            proposed_updates: crate::update::ProposedUpdates::default(),
            config: value.config,
            tee_state: TeeState {
                allowed_code_hashes: AllowedCodeHashes::default(),
                historical_code_hashes: vec![],
                votes: CodeHashesVotes::default(),
            },
        }
    }
}
