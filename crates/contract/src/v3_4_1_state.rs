//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.
//!
//! ## Changes in 3.3.2
//! - `Participants` struct changed from serializing participants as
//!   `Vec<(AccountId, ParticipantId, ParticipantInfo)>` to
//!   `BTreeMap<AccountId, ParticipantData>` where `ParticipantData { id, info }`.
//! - `StaleData` was cleaned up (participant_attestations field removed).

use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types as dtos;
use near_account_id::AccountId;
use near_sdk::{env, store::LookupMap};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainConfig, DomainRegistry},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        participants::{ParticipantId, ParticipantInfo},
        signature::{SignatureRequest, YieldIndex},
        thresholds::Threshold,
        votes::ThresholdParametersVotes,
    },
    state::key_event::KeyEventInstance,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StorageKey,
};

/// Old Participants format that serialized as Vec.
#[derive(Debug, BorshDeserialize)]
pub struct OldParticipants {
    next_id: ParticipantId,
    participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

impl From<OldParticipants> for crate::primitives::participants::Participants {
    fn from(old: OldParticipants) -> Self {
        crate::primitives::participants::Participants::init(old.next_id, old.participants)
            .expect("Migrated participants should be valid")
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

/// Old ThresholdParametersVotes using OldThresholdParameters.
/// Needed because ThresholdParameters contains Participants, whose Borsh
/// layout changed from Vec to BTreeMap.
#[derive(Debug, BorshDeserialize)]
pub struct OldThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, OldThresholdParameters>,
}

impl From<OldThresholdParametersVotes> for ThresholdParametersVotes {
    fn from(old: OldThresholdParametersVotes) -> Self {
        let converted = old
            .proposal_by_account
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect();
        ThresholdParametersVotes {
            proposal_by_account: converted,
        }
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
    pub parameters_votes: OldThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for crate::state::running::RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        crate::state::running::RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters.into(),
            parameters_votes: old.parameters_votes.into(),
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

/// StaleData in v3.4.1 is empty (participant_attestations was cleaned up in 3.3.2 → 3.4.0).
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
struct StaleData {}

/// Old MpcContract with OldProtocolContractState.
#[derive(Debug, BorshDeserialize)]
#[allow(dead_code)] // stale_data field is needed for deserialization but dropped during migration
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
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

        let crate::ProtocolContractState::Running(_running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        Self {
            protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequests,
            ),
            proposed_updates: value.proposed_updates,
            foreign_chain_policy: value.foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            // Old stale_data is dropped, new StaleData is empty
            stale_data: crate::StaleData {},
        }
    }
}
