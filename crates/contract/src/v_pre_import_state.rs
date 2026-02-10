//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before the
//! `import_domain_votes` field was added to `RunningContractState`.
//!
//! ## Guideline
//! Only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types::{self as dtos, VerifyForeignTransactionRequest};
use near_sdk::{
    env,
    store::LookupMap,
};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedAccountId, EpochId, KeyForDomain, Keyset},
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
        votes::ThresholdParametersVotes,
    },
    state::{initializing::InitializingContractState, key_event::KeyEvent},
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes,
};

/// The old `RunningContractState` layout, before `import_domain_votes` was added.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct OldRunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: ThresholdParameters,
    pub parameters_votes: ThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for crate::state::running::RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        let mut state = Self::new(old.domains, old.keyset, old.parameters);
        state.parameters_votes = old.parameters_votes;
        state.add_domains_votes = old.add_domains_votes;
        state.previously_cancelled_resharing_epoch_id = old.previously_cancelled_resharing_epoch_id;
        state
    }
}

/// The old `ResharingContractState` layout, which embeds `OldRunningContractState`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldResharingContractState {
    pub previous_running_state: OldRunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
}

impl From<OldResharingContractState> for crate::state::resharing::ResharingContractState {
    fn from(old: OldResharingContractState) -> Self {
        Self {
            previous_running_state: old.previous_running_state.into(),
            reshared_keys: old.reshared_keys,
            resharing_key: old.resharing_key,
            cancellation_requests: old.cancellation_requests,
        }
    }
}

/// The old `ProtocolContractState` using `OldRunningContractState`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(OldResharingContractState),
}

impl From<OldProtocolContractState> for crate::state::ProtocolContractState {
    fn from(old: OldProtocolContractState) -> Self {
        match old {
            OldProtocolContractState::NotInitialized => {
                crate::state::ProtocolContractState::NotInitialized
            }
            OldProtocolContractState::Initializing(state) => {
                crate::state::ProtocolContractState::Initializing(state)
            }
            OldProtocolContractState::Running(state) => {
                crate::state::ProtocolContractState::Running(state.into())
            }
            OldProtocolContractState::Resharing(state) => {
                crate::state::ProtocolContractState::Resharing(state.into())
            }
        }
    }
}

/// The current `StaleData` layout (empty after v3_3_2 cleanup).
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
struct StaleData {}

/// The previous `MpcContract` layout. Only `protocol_state` differs from the current
/// layout (it uses `OldProtocolContractState` which lacks `import_domain_votes`).
/// All other fields match the current `MpcContract` exactly.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: dtos::ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let protocol_state: crate::state::ProtocolContractState = value.protocol_state.into();

        let crate::state::ProtocolContractState::Running(_running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        Self {
            protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy: value.foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {},
        }
    }
}
