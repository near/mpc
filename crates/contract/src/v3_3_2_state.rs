//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The migration handles the change from Vec-based Participants serialization to BTreeMap-based.
//!
//! ## Changes in 3.3.2
//! - `Participants` struct changed from serializing participants as
//!   `Vec<(AccountId, ParticipantId, ParticipantInfo)>` to
//!   `BTreeMap<AccountId, ParticipantData>` where `ParticipantData { id, info }`.
//! - `StaleData` was cleaned up (participant_attestations field removed).

use borsh::BorshDeserialize;
use mpc_attestation::attestation::Attestation;
use near_account_id::AccountId;
use near_sdk::store::IterableMap;
use std::collections::{BTreeSet, HashSet};

use crate::{
    primitives::{
        domain::{AddDomainsVotes, DomainConfig, DomainRegistry},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        thresholds::Threshold,
        votes::ThresholdParametersVotes,
    },
    state::key_event::KeyEventInstance,
    tee::tee_state::NodeId,
};

// Re-use unchanged types from current crate
use crate::primitives::participants::{ParticipantId, ParticipantInfo};

/// Old Participants format that serialized as Vec.
#[derive(Debug, BorshDeserialize)]
pub struct OldParticipants {
    next_id: ParticipantId,
    participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

impl From<OldParticipants> for crate::primitives::participants::Participants {
    fn from(old: OldParticipants) -> Self {
        crate::primitives::participants::Participants::init(old.next_id, old.participants)
    }
}

/// Old ThresholdParameters using OldParticipants.
#[derive(Debug, BorshDeserialize)]
pub struct OldThresholdParameters {
    participants: OldParticipants,
    threshold: Threshold,
}

impl From<OldThresholdParameters> for crate::primitives::thresholds::ThresholdParameters {
    fn from(old: OldThresholdParameters) -> Self {
        crate::primitives::thresholds::ThresholdParameters::new_unvalidated(
            old.participants.into(),
            old.threshold,
        )
    }
}

/// Old KeyEvent using OldThresholdParameters.
#[derive(Debug, BorshDeserialize)]
pub struct OldKeyEvent {
    epoch_id: EpochId,
    domain: DomainConfig,
    parameters: OldThresholdParameters,
    instance: Option<KeyEventInstance>,
    next_attempt_id: AttemptId,
}

impl From<OldKeyEvent> for crate::state::key_event::KeyEvent {
    fn from(old: OldKeyEvent) -> Self {
        crate::state::key_event::KeyEvent::from_migration(
            old.epoch_id,
            old.domain,
            old.parameters.into(),
            old.instance,
            old.next_attempt_id,
        )
    }
}

/// Old RunningContractState using OldThresholdParameters.
#[derive(Debug, BorshDeserialize)]
pub struct OldRunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: OldThresholdParameters,
    pub parameters_votes: ThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for crate::state::running::RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        crate::state::running::RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters.into(),
            parameters_votes: old.parameters_votes,
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// Old InitializingContractState using OldKeyEvent.
#[derive(Debug, BorshDeserialize)]
pub struct OldInitializingContractState {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: OldKeyEvent,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

impl From<OldInitializingContractState> for crate::state::initializing::InitializingContractState {
    fn from(old: OldInitializingContractState) -> Self {
        crate::state::initializing::InitializingContractState {
            domains: old.domains,
            epoch_id: old.epoch_id,
            generated_keys: old.generated_keys,
            generating_key: old.generating_key.into(),
            cancel_votes: old.cancel_votes,
        }
    }
}

/// Old ResharingContractState using OldRunningContractState and OldKeyEvent.
#[derive(Debug, BorshDeserialize)]
pub struct OldResharingContractState {
    pub previous_running_state: OldRunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: OldKeyEvent,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
}

impl From<OldResharingContractState> for crate::state::resharing::ResharingContractState {
    fn from(old: OldResharingContractState) -> Self {
        crate::state::resharing::ResharingContractState {
            previous_running_state: old.previous_running_state.into(),
            reshared_keys: old.reshared_keys,
            resharing_key: old.resharing_key.into(),
            cancellation_requests: old.cancellation_requests,
        }
    }
}

/// Old ProtocolContractState enum.
#[derive(Debug, BorshDeserialize)]
pub enum OldProtocolContractState {
    NotInitialized,
    Initializing(OldInitializingContractState),
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
                crate::state::ProtocolContractState::Initializing(state.into())
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

/// Old StaleData that contained participant_attestations.
/// The new StaleData is empty after cleanup.
#[derive(Debug, Default, BorshDeserialize)]
#[allow(dead_code)] // Fields are needed for deserialization but not read directly
struct OldStaleData {
    /// Holds the TEE attestations from the previous contract version.
    /// This is stored as an `Option` so it can be `.take()`n during the cleanup process,
    /// ensuring the `IterableMap` handle is properly dropped.
    participant_attestations: Option<IterableMap<near_sdk::PublicKey, (NodeId, Attestation)>>,
}

/// Old MpcContract with OldProtocolContractState and OldStaleData.
#[derive(Debug, BorshDeserialize)]
#[allow(dead_code)] // stale_data field is needed for deserialization but dropped during migration
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: near_sdk::store::LookupMap<
        crate::primitives::signature::SignatureRequest,
        crate::primitives::signature::YieldIndex,
    >,
    pending_ckd_requests: near_sdk::store::LookupMap<
        crate::primitives::ckd::CKDRequest,
        crate::primitives::signature::YieldIndex,
    >,
    proposed_updates: crate::update::ProposedUpdates,
    config: crate::Config,
    tee_state: crate::TeeState,
    accept_requests: bool,
    node_migrations: crate::node_migrations::NodeMigrations,
    stale_data: OldStaleData,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        Self {
            protocol_state: value.protocol_state.into(),
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            proposed_updates: value.proposed_updates,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            // Old stale_data is dropped, new StaleData is empty
            stale_data: crate::StaleData::default(),
        }
    }
}
