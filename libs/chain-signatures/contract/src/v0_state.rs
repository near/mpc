//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.
use attestation::attestation::{Attestation, MockAttestation};
use near_account_id::AccountId;
use near_sdk::store::IterableMap;
use near_sdk::{env, near, store::LookupMap};
use std::collections::HashSet;

use crate::legacy_contract_state::ConfigV1;
use crate::primitives::votes::ThresholdParametersVotes;
use crate::primitives::{
    domain::{AddDomainsVotes, DomainRegistry},
    key_state::{KeyForDomain, Keyset},
    thresholds::ThresholdParameters,
};
use crate::state::{initializing::InitializingContractState, key_event::KeyEvent};
use crate::storage_keys::StorageKey;
use crate::update::UpdateId;
use crate::{
    primitives::signature::{SignatureRequest, YieldIndex},
    MpcContract,
};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ResharingContractState {
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct RunningContractState {
    /// The domains for which we have a key ready for signature processing.
    pub domains: DomainRegistry,
    /// The keys that are currently in use; for each domain provides an unique identifier for a
    /// distributed key, so that the nodes can identify which local keyshare to use.
    pub keyset: Keyset,
    /// The current participants and threshold.
    pub parameters: ThresholdParameters,
    /// Votes for proposals for a new set of participants and threshold.
    pub parameters_votes: ThresholdParametersVotes,
    /// Votes for proposals to add new domains.
    pub add_domains_votes: AddDomainsVotes,
}
#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

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
pub struct TeeState {
    allowed_tee_proposals: crate::tee::proposal::AllowedDockerImageHashes,
    historical_tee_proposals: Vec<crate::tee::proposal::LauncherDockerComposeHash>,
    votes: crate::tee::proposal::CodeHashesVotes,
}

impl From<TeeState> for crate::TeeState {
    fn from(value: TeeState) -> Self {
        Self {
            allowed_docker_image_hashes: value.allowed_tee_proposals,
            allowed_launcher_compose_hashes: value.historical_tee_proposals,
            votes: value.votes,
            participants_attestations: IterableMap::new(StorageKey::TeeParticipantAttestation),
        }
    }
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MpcContractV1 {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    proposed_updates: crate::update::ProposedUpdates,
    config: Config,
    tee_state: TeeState,
}

impl From<RunningContractState> for crate::RunningContractState {
    fn from(value: RunningContractState) -> Self {
        Self {
            domains: value.domains,
            keyset: value.keyset,
            parameters: value.parameters,
            parameters_votes: crate::primitives::votes::ThresholdParametersVotes::default(),
            add_domains_votes: value.add_domains_votes,
            previously_cancelled_resharing_epoch_id: None,
        }
    }
}

impl From<ProtocolContractState> for crate::ProtocolContractState {
    fn from(value: ProtocolContractState) -> Self {
        match value {
            ProtocolContractState::Running(running) => {
                crate::ProtocolContractState::Running(running.into())
            }
            _ => env::panic_str("not supported"),
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: u64,
}

impl From<Config> for crate::config::Config {
    fn from(old_config: Config) -> Self {
        crate::config::Config {
            key_event_timeout_blocks: old_config.key_event_timeout_blocks,
            ..Default::default()
        }
    }
}

impl From<MpcContractV1> for MpcContract {
    fn from(value: MpcContractV1) -> Self {
        let config = value.config.into();
        let mut tee_state = crate::TeeState::default();

        let protocol_state = value.protocol_state.into();

        let crate::ProtocolContractState::Running(running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        // For the soft release we give every participant a mocked attestation.
        // For more context see: https://github.com/near/mpc/issues/1052
        {
            let participant_account_ids = running_state
                .parameters
                .participants()
                .participants()
                .iter()
                .map(|(account_id, _, _)| account_id); // This API structure is so so bad. Create a TODO to revisit this.

            for participant_account_id in participant_account_ids {
                tee_state.add_participant(
                    participant_account_id.clone(),
                    Attestation::Mock(MockAttestation::Valid),
                )
            }
        }

        Self {
            protocol_state,
            pending_signature_requests: value.pending_requests,
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequests),
            proposed_updates: value.proposed_updates,
            config,
            tee_state,
            accept_requests: true,
        }
    }
}
