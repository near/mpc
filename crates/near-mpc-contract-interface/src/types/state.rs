//! DTO types for protocol contract state.
//!
//! These types mirror the internal contract state types and are used for JSON serialization
//! in the contract's public API (e.g., the `state()` view function).

use crate::types::PublicKeyExtended;
use crate::types::participants::Participants;
use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

use super::primitives::DomainId;

// =============================================================================
// Simple Wrapper Types (newtypes)
// =============================================================================

/// Epoch identifier for key generation/resharing cycles.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct EpochId(pub u64);

impl EpochId {
    pub const fn new(epoch_id: u64) -> Self {
        EpochId(epoch_id)
    }

    pub fn get(&self) -> u64 {
        self.0
    }

    pub const fn next(&self) -> Self {
        EpochId(self.0 + 1)
    }
}

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Attempt identifier within a key event.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AttemptId(pub u64);

impl AttemptId {
    pub fn new() -> Self {
        AttemptId(0)
    }

    pub fn next(&self) -> Self {
        AttemptId(self.0 + 1)
    }

    pub fn get(&self) -> u64 {
        self.0
    }

    /// Returns the AttemptId used for legacy keyshares (before key events existed).
    pub fn legacy_attempt_id() -> Self {
        AttemptId(0)
    }
}

impl Default for AttemptId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Threshold value for distributed key operations.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Threshold(pub u64);

/// A participant ID that has been authenticated (i.e., the caller is this participant).
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AuthenticatedParticipantId(pub crate::types::participants::ParticipantId);

/// An account ID that has been authenticated (i.e., the caller is this account).
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AuthenticatedAccountId(pub AccountId);

// =============================================================================
// Domain Types
// =============================================================================

/// Supported signature schemes.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum SignatureScheme {
    Secp256k1,
    Ed25519,
    Bls12381,
    /// Robust ECDSA variant.
    V2Secp256k1,
}

/// The purpose that a domain serves.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema, schemars::JsonSchema)
)]
pub enum DomainPurpose {
    /// Domain is used by `sign()`.
    Sign,
    /// Domain is used by `verify_foreign_transaction()`.
    ForeignTx,
    /// Domain is used by `request_app_private_key()` (Confidential Key Derivation).
    CKD,
}

/// Configuration for a signature domain.
#[derive(
    Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
    /// `None` when reading state from an old contract that predates domain purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<DomainPurpose>,
}

/// Registry of all signature domains.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DomainRegistry {
    pub domains: Vec<DomainConfig>,
    pub next_domain_id: u64,
}

// =============================================================================
// Key State Types
// =============================================================================

/// A public key for a specific domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct KeyForDomain {
    pub domain_id: DomainId,
    pub key: PublicKeyExtended,
    pub attempt: AttemptId,
}

/// Set of keys for the current epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Keyset {
    pub epoch_id: EpochId,
    pub domains: Vec<KeyForDomain>,
}

impl Keyset {
    pub fn get_domain_ids(&self) -> Vec<DomainId> {
        self.domains.iter().map(|domain| domain.domain_id).collect()
    }

    /// Returns the public key for the given domain, or an error if the domain is not found.
    pub fn public_key(&self, domain_id: DomainId) -> Result<PublicKeyExtended, String> {
        self.domains
            .iter()
            .find(|k| k.domain_id == domain_id)
            .map(|k| k.key.clone())
            .ok_or_else(|| format!("Domain {:?} not found in keyset", domain_id))
    }
}

/// Identifier for a key event (generation or resharing attempt).
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct KeyEventId {
    pub epoch_id: EpochId,
    pub domain_id: DomainId,
    pub attempt_id: AttemptId,
}

impl KeyEventId {
    pub fn new(epoch_id: EpochId, domain_id: DomainId, attempt_id: AttemptId) -> Self {
        KeyEventId {
            epoch_id,
            domain_id,
            attempt_id,
        }
    }
}

// =============================================================================
// Threshold/Participants Types
// =============================================================================

/// Threshold parameters for distributed key operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ThresholdParameters {
    pub participants: Participants,
    pub threshold: Threshold,
}

// =============================================================================
// Voting Types
// =============================================================================

/// Votes for threshold parameter changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ThresholdParametersVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedAccountId, ThresholdParameters>,
}

/// Votes for adding new domains.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AddDomainsVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<DomainConfig>>,
}

// =============================================================================
// Key Event Types
// =============================================================================

/// State of a key generation/resharing instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct KeyEventInstance {
    pub attempt_id: AttemptId,
    pub started_in: u64,
    pub expires_on: u64,
    pub completed: BTreeSet<AuthenticatedParticipantId>,
    pub public_key: Option<PublicKeyExtended>,
}

/// Key generation or resharing event state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct KeyEvent {
    pub epoch_id: EpochId,
    pub domain: DomainConfig,
    pub parameters: ThresholdParameters,
    pub instance: Option<KeyEventInstance>,
    pub next_attempt_id: AttemptId,
}

// =============================================================================
// Contract State Types
// =============================================================================

/// State when the contract is generating keys for new domains.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct InitializingContractState {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: KeyEvent,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

/// State when the contract is ready for signature operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct RunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: ThresholdParameters,
    pub parameters_votes: ThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

/// State when the contract is resharing keys to new participants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ResharingContractState {
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
}

/// The main protocol contract state enum.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl fmt::Display for ProtocolContractState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn write_params(f: &mut fmt::Formatter<'_>, parameters: &ThresholdParameters) -> fmt::Result {
            writeln!(f, "    Participants:")?;
            for (account_id, id, info) in &parameters.participants.participants {
                writeln!(f, "      ID {}: {} ({})", id.0, account_id.0, info.url)?;
            }
            writeln!(f, "    Threshold: {}", parameters.threshold.0)
        }

        fn write_key_event_progress(
            f: &mut fmt::Formatter<'_>,
            key_event: &KeyEvent,
            completed_keys: &[KeyForDomain],
            domains: &[DomainConfig],
            action: &str,
            past_action: &str,
        ) -> fmt::Result {
            writeln!(f, "  Domains:")?;
            #[expect(clippy::comparison_chain)]
            for (i, domain) in domains.iter().enumerate() {
                write!(f, "    Domain {}: {:?}, ", domain.id, domain.scheme)?;
                if i < completed_keys.len() {
                    writeln!(f, "{past_action} (attempt ID {})", completed_keys[i].attempt)?;
                } else if i == completed_keys.len() {
                    write!(f, "{action} key: ")?;
                    if let Some(instance) = &key_event.instance {
                        writeln!(f, "active; current attempt ID: {}", instance.attempt_id)?;
                    } else {
                        writeln!(
                            f,
                            "not active; next attempt ID: {}",
                            key_event.next_attempt_id
                        )?;
                    }
                } else {
                    writeln!(f, "queued for {action}")?;
                }
            }
            Ok(())
        }

        match self {
            ProtocolContractState::NotInitialized => {
                writeln!(f, "Contract is not initialized")
            }
            ProtocolContractState::Initializing(state) => {
                writeln!(f, "Contract is in Initializing state (key generation)")?;
                writeln!(f, "  Epoch: {}", state.generating_key.epoch_id)?;
                write_key_event_progress(
                    f,
                    &state.generating_key,
                    &state.generated_keys,
                    &state.domains.domains,
                    "generating",
                    "key generated",
                )?;
                writeln!(f, "  Parameters:")?;
                write_params(f, &state.generating_key.parameters)?;
                writeln!(f, "  Warning: this tool does not calculate automatic timeouts for key generation attempts")
            }
            ProtocolContractState::Running(state) => {
                writeln!(f, "Contract is in Running state")?;
                writeln!(f, "  Epoch: {}", state.keyset.epoch_id)?;
                writeln!(f, "  Keyset:")?;
                for (domain, key) in
                    state.domains.domains.iter().zip(state.keyset.domains.iter())
                {
                    writeln!(
                        f,
                        "    Domain {}: {:?}, key from attempt {}",
                        domain.id, domain.scheme, key.attempt
                    )?;
                }
                writeln!(f, "  Parameters:")?;
                write_params(f, &state.parameters)
            }
            ProtocolContractState::Resharing(state) => {
                writeln!(f, "Contract is in Resharing state")?;
                writeln!(
                    f,
                    "  Epoch transition: original {} --> prospective {}",
                    state.previous_running_state.keyset.epoch_id,
                    state.resharing_key.epoch_id
                )?;
                write_key_event_progress(
                    f,
                    &state.resharing_key,
                    &state.reshared_keys,
                    &state.previous_running_state.domains.domains,
                    "resharing",
                    "reshared",
                )?;
                writeln!(f, "  Previous Parameters:")?;
                write_params(f, &state.previous_running_state.parameters)?;
                writeln!(f, "  Proposed Parameters:")?;
                write_params(f, &state.resharing_key.parameters)?;
                writeln!(f, "  Warning: this tool does not calculate automatic timeouts for resharing attempts")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_state_serialization() {
        let state = ProtocolContractState::NotInitialized;
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("NotInitialized"));
    }
}
