//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types as dtos;
use near_sdk::{env, near, store::LookupMap};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    errors::{Error, InvalidParameters},
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{infer_purpose_from_scheme, DomainId, SignatureScheme},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        signature::{Tweak, YieldIndex},
        thresholds::ThresholdParameters,
        votes::ThresholdParametersVotes,
    },
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StorageKey,
};

/// Old `StaleData` was an empty struct — must match the on-chain borsh layout exactly.
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
struct OldStaleData {}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: dtos::ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: OldStaleData,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let protocol_state = value.protocol_state.into_current();

        let crate::ProtocolContractState::Running(_running_state) = &protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        Self {
            protocol_state,
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV3),
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
            stale_data: crate::StaleData {
                pending_signature_requests_pre_upgrade: value.pending_signature_requests,
            },
            metrics: Default::default(),
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
            purpose: infer_purpose_from_scheme(self.scheme),
            id: self.id,
            scheme: self.scheme,
        }
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize)]
pub struct SignatureRequest {
    pub tweak: Tweak,
    pub payload: Payload,
    pub domain_id: DomainId,
}

/// A signature payload; the right payload must be passed in for the curve.
/// The json encoding for this payload converts the bytes to hex string.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub enum Payload {
    Ecdsa(
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "[u8; 32]"),
            borsh(schema(with_funcs(
                declaration = "<[u8; 32] as ::borsh::BorshSchema>::declaration",
                definitions = "<[u8; 32] as ::borsh::BorshSchema>::add_definitions_recursively"
            ),))
        )]
        Bytes<32, 32>,
    ),
    Eddsa(
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>"),
            borsh(schema(with_funcs(
                declaration = "<Vec<u8> as ::borsh::BorshSchema>::declaration",
                definitions = "<Vec<u8> as ::borsh::BorshSchema>::add_definitions_recursively"
            ),))
        )]
        Bytes<32, 1232>,
    ),
}

impl<const MIN_LEN: usize, const MAX_LEN: usize> Bytes<MIN_LEN, MAX_LEN> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < MIN_LEN || bytes.len() > MAX_LEN {
            return Err(InvalidParameters::MalformedPayload.into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A byte array with a statically encoded minimum and maximum length.
/// The `new` function as well as json deserialization checks that the length is within bounds.
/// The borsh deserialization does not perform such checks, as the borsh serialization is only
/// used for internal contract storage.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh])]
pub struct Bytes<const MIN_LEN: usize, const MAX_LEN: usize>(Vec<u8>);

impl<const MIN_LEN: usize, const MAX_LEN: usize> near_sdk::serde::Serialize
    for Bytes<MIN_LEN, MAX_LEN>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: near_sdk::serde::Serializer,
    {
        near_sdk::serde::Serialize::serialize(&hex::encode(&self.0), serializer)
    }
}

impl<'de, const MIN_LEN: usize, const MAX_LEN: usize> near_sdk::serde::Deserialize<'de>
    for Bytes<MIN_LEN, MAX_LEN>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: near_sdk::serde::Deserializer<'de>,
    {
        let s = <String as near_sdk::serde::Deserialize>::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(near_sdk::serde::de::Error::custom)?;
        Self::new(bytes).map_err(near_sdk::serde::de::Error::custom)
    }
}

impl From<&crate::primitives::signature::SignatureRequest> for SignatureRequest {
    fn from(request: &crate::primitives::signature::SignatureRequest) -> Self {
        let payload = match &request.payload {
            crate::primitives::signature::Payload::Ecdsa(bytes) => {
                Payload::Ecdsa(Bytes(bytes.as_slice().to_vec()))
            }
            crate::primitives::signature::Payload::Eddsa(bytes) => {
                Payload::Eddsa(Bytes(bytes.as_slice().to_vec()))
            }
        };
        SignatureRequest {
            tweak: request.tweak.clone(),
            payload,
            domain_id: request.domain_id,
        }
    }
}
