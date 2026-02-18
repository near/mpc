//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before `DomainPurpose`
//! was added to `DomainConfig`.
//!
//! ## Guideline
//! Only the structures that have changed are copied here. Everything else is imported
//! from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types as dtos;
use near_sdk::{env, near, store::LookupMap};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{DomainId, DomainPurpose, SignatureScheme},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
        votes::ThresholdParametersVotes,
    },
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StaleData,
};

// ---------------------------------------------------------------------------
// Snapshot of types that CHANGED (DomainConfig lost the `purpose` field)
// ---------------------------------------------------------------------------

/// Old `DomainConfig` without the `purpose` field.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
}

impl DomainConfig {
    fn into_current(self) -> crate::primitives::domain::DomainConfig {
        crate::primitives::domain::DomainConfig {
            purpose: DomainPurpose::infer_from_scheme(self.scheme),
            id: self.id,
            scheme: self.scheme,
        }
    }
}

/// Old `DomainRegistry` embedding old `DomainConfig`.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRegistry {
    domains: Vec<DomainConfig>,
    next_domain_id: u64,
}

impl DomainRegistry {
    fn into_current(self) -> crate::primitives::domain::DomainRegistry {
        let domains: Vec<crate::primitives::domain::DomainConfig> =
            self.domains.into_iter().map(|d| d.into_current()).collect();
        crate::primitives::domain::DomainRegistry::from_raw_validated(domains, self.next_domain_id)
            .expect("old state must have valid domain registry")
    }
}

/// Old `AddDomainsVotes` embedding old `DomainConfig`.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddDomainsVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<DomainConfig>>,
}

impl AddDomainsVotes {
    fn into_current(self) -> crate::primitives::domain::AddDomainsVotes {
        crate::primitives::domain::AddDomainsVotes {
            proposal_by_account: self
                .proposal_by_account
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(|d| d.into_current()).collect()))
                .collect(),
        }
    }
}

/// Old `KeyEvent` embedding old `DomainConfig`.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct KeyEvent {
    epoch_id: EpochId,
    domain: DomainConfig,
    parameters: ThresholdParameters,
    instance: Option<crate::state::key_event::KeyEventInstance>,
    next_attempt_id: AttemptId,
}

impl KeyEvent {
    fn into_current(self) -> crate::state::key_event::KeyEvent {
        crate::state::key_event::KeyEvent::from_raw(
            self.epoch_id,
            self.domain.into_current(),
            self.parameters,
            self.instance,
            self.next_attempt_id,
        )
    }
}

/// Old `RunningContractState` embedding old `DomainRegistry` + `AddDomainsVotes`.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: ThresholdParameters,
    pub parameters_votes: ThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl RunningContractState {
    fn into_current(self) -> crate::state::running::RunningContractState {
        crate::state::running::RunningContractState {
            domains: self.domains.into_current(),
            keyset: self.keyset,
            parameters: self.parameters,
            parameters_votes: self.parameters_votes,
            add_domains_votes: self.add_domains_votes.into_current(),
            previously_cancelled_resharing_epoch_id: self.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// Old `InitializingContractState` embedding old `DomainRegistry` + `KeyEvent`.
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: KeyEvent,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

impl InitializingContractState {
    fn into_current(self) -> crate::state::initializing::InitializingContractState {
        crate::state::initializing::InitializingContractState {
            domains: self.domains.into_current(),
            epoch_id: self.epoch_id,
            generated_keys: self.generated_keys,
            generating_key: self.generating_key.into_current(),
            cancel_votes: self.cancel_votes,
        }
    }
}

/// Old `ResharingContractState` embedding old `RunningContractState` + `KeyEvent`.
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct ResharingContractState {
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
}

impl ResharingContractState {
    fn into_current(self) -> crate::state::resharing::ResharingContractState {
        crate::state::resharing::ResharingContractState {
            previous_running_state: self.previous_running_state.into_current(),
            reshared_keys: self.reshared_keys,
            resharing_key: self.resharing_key.into_current(),
            cancellation_requests: self.cancellation_requests,
        }
    }
}

/// Old `ProtocolContractState` wrapping the old sub-states.
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolContractState {
    fn into_current(self) -> crate::state::ProtocolContractState {
        match self {
            Self::NotInitialized => crate::state::ProtocolContractState::NotInitialized,
            Self::Initializing(s) => {
                crate::state::ProtocolContractState::Initializing(s.into_current())
            }
            Self::Running(s) => crate::state::ProtocolContractState::Running(s.into_current()),
            Self::Resharing(s) => crate::state::ProtocolContractState::Resharing(s.into_current()),
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level contract struct (old layout)
// ---------------------------------------------------------------------------

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
    node_migrations: NodeMigrations,
    stale_data: StaleData,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let protocol_state = value.protocol_state.into_current();

        let crate::ProtocolContractState::Running(_running_state) = &protocol_state else {
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
