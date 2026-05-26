//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{
    self as dtos, Ed25519PublicKey, VerifyForeignTransactionRequest,
};
use near_sdk::{
    env,
    store::{IterableMap, LookupMap},
};
use std::collections::{BTreeMap, HashSet};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::DomainRegistry,
        key_state::{
            AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain, Keyset,
        },
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
    },
    state::{key_event::KeyEvent, ProtocolContractState as NewProtocolContractState},
    tee::{
        measurements::{AllowedMeasurements, ContractExpectedMeasurements},
        proposal::{AllowedDockerImageHashes, AllowedLauncherImages, LauncherVoteAction},
        tee_state::{NodeAttestation, TeeState},
    },
    update::ProposedUpdates,
    Config, SupportedForeignChainsByNode,
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

/// `3.10.0`'s `MpcContract` layout. Differs from the current `MpcContract` in two
/// places: the legacy `RunningContractState` carried inline vote maps, and the
/// `TeeState` votes were `BTreeMap`-backed. Both are reshaped on migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    legacy_pending_requests: LegacyPendingRequests,
    metrics: dtos::Metrics,
    foreign_chain_rpc_whitelist: OldForeignChainRpcWhitelist,
}

/// `3.10.0`'s `ProtocolContractState`. Differs from the new layout only in the
/// `RunningContractState` shape (carries inline vote maps). Reproduced here so the
/// migration can borsh-deserialize the legacy bytes faithfully.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum OldProtocolContractState {
    NotInitialized,
    Initializing(crate::state::initializing::InitializingContractState),
    Running(OldRunningContractState),
    Resharing(OldResharingContractState),
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldRunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: ThresholdParameters,
    pub parameters_votes: OldThresholdParametersVotes,
    pub add_domains_votes: OldAddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldResharingContractState {
    pub previous_running_state: OldRunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
}

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct OldThresholdParametersVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedAccountId, ThresholdParameters>,
}

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct OldAddDomainsVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<dtos::DomainConfig>>,
}

/// `3.10.0`'s `TeeState`. The vote stores are inline `BTreeMap`s; the new layout
/// uses `IterableMap`-backed `Votes<V>` and discards in-flight votes on migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldTeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) allowed_launcher_images: AllowedLauncherImages,
    pub(crate) votes: OldCodeHashesVotes,
    pub(crate) launcher_votes: OldLauncherHashVotes,
    pub(crate) stored_attestations: IterableMap<Ed25519PublicKey, NodeAttestation>,
    pub(crate) allowed_measurements: AllowedMeasurements,
    pub(crate) measurement_votes: OldMeasurementVotes,
}

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct OldCodeHashesVotes {
    pub proposal_by_account:
        BTreeMap<AuthenticatedParticipantId, mpc_primitives::hash::NodeImageHash>,
}

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct OldLauncherHashVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, LauncherVoteAction>,
}

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct OldMeasurementVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, OldMeasurementVoteAction>,
}

/// Mirror of the new `MeasurementVoteAction` enum used only for legacy deserialization.
/// The variant order and payload type match the live type, so on-disk bytes line up.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum OldMeasurementVoteAction {
    Add(ContractExpectedMeasurements),
    Remove(ContractExpectedMeasurements),
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

impl From<OldRunningContractState> for crate::state::running::RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        // In-flight governance / add-domain votes are transient: discard them. The
        // new top-level `ContractVotes` field carries fresh hash-based stores.
        let _ = old.parameters_votes;
        let _ = old.add_domains_votes;
        let mut state = Self::new(old.domains, old.keyset, old.parameters);
        state.previously_cancelled_resharing_epoch_id = old.previously_cancelled_resharing_epoch_id;
        state
    }
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

impl From<OldProtocolContractState> for NewProtocolContractState {
    fn from(old: OldProtocolContractState) -> Self {
        match old {
            OldProtocolContractState::NotInitialized => NewProtocolContractState::NotInitialized,
            OldProtocolContractState::Initializing(state) => {
                NewProtocolContractState::Initializing(state)
            }
            OldProtocolContractState::Running(state) => {
                NewProtocolContractState::Running(state.into())
            }
            OldProtocolContractState::Resharing(state) => {
                NewProtocolContractState::Resharing(state.into())
            }
        }
    }
}

impl From<OldTeeState> for TeeState {
    fn from(old: OldTeeState) -> Self {
        // Drop in-flight TEE votes — they are transient. The applied whitelists and
        // the attestation registry move forward unchanged. Moving `stored_attestations`
        // preserves both the IterableMap metadata and the underlying storage prefix.
        let _ = (old.votes, old.launcher_votes, old.measurement_votes);
        TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: Default::default(),
            launcher_votes: Default::default(),
            stored_attestations: old.stored_attestations,
            allowed_measurements: old.allowed_measurements,
            measurement_votes: Default::default(),
        }
    }
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, OldProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        // `3.10.0` had no vote endpoint, so `old.foreign_chain_rpc_whitelist.entries`
        // is guaranteed empty. Drop it and default-initialize the current reshaped
        // whitelist (empty `entries`, empty `votes.pending`).
        crate::MpcContract {
            protocol_state: old.protocol_state.into(),
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config,
            tee_state: old.tee_state.into(),
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            metrics: old.metrics,
            foreign_chain_rpc_whitelist: Default::default(),
            votes: Default::default(),
        }
    }
}
