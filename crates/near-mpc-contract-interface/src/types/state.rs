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

use super::primitives::DomainId;

// =============================================================================
// Simple Wrapper Types (newtypes)
// =============================================================================

pub use mpc_primitives::{AttemptId, EpochId, GovernanceThreshold, ReconstructionThreshold};

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

pub use mpc_primitives::domain::{Curve, Protocol};

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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct DomainConfig {
    pub id: DomainId,
    pub protocol: Protocol,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub purpose: DomainPurpose,
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

pub use mpc_primitives::KeyEventId;
pub use near_mpc_crypto_types::{KeyForDomain, Keyset};

// =============================================================================
// GovernanceThreshold/Participants Types
// =============================================================================

/// GovernanceThreshold parameters for distributed key operations: the current
/// participant set and the governance threshold. This is the stored,
/// always-current shape; per-domain reconstruction-threshold *proposals* live
/// on [`ProposedGovernanceThresholdParameters`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct GovernanceThresholdParameters {
    pub participants: Participants,
    pub governance_threshold: GovernanceThreshold,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct GovernanceThresholdParametersCompat {
    pub participants: Participants,
    pub threshold: GovernanceThreshold,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<GovernanceThresholdParametersCompat> for GovernanceThresholdParameters {
    fn from(value: GovernanceThresholdParametersCompat) -> Self {
        Self {
            participants: value.participants,
            governance_threshold: value.threshold,
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<GovernanceThresholdParameters> for GovernanceThresholdParametersCompat {
    fn from(value: GovernanceThresholdParameters) -> Self {
        Self {
            participants: value.participants,
            threshold: value.governance_threshold,
        }
    }
}

/// A proposed set of threshold parameters submitted to `vote_new_parameters`:
/// the proposed [`GovernanceThresholdParameters`] plus per-domain `ReconstructionThreshold`
/// updates for the resharing it would trigger. An empty
/// `per_domain_reconstruction_thresholds` keeps the current ones; a populated map
/// must reference only existing domains (contract-validated), is applied to the
/// `DomainRegistry` on resharing, and never persists onto the stored
/// [`GovernanceThresholdParameters`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ProposedGovernanceThresholdParameters {
    pub parameters: GovernanceThresholdParameters,
    #[serde(default)]
    pub per_domain_reconstruction_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ProposedGovernanceThresholdParametersCompat {
    pub parameters: GovernanceThresholdParametersCompat,
    #[serde(default)]
    pub per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<ProposedGovernanceThresholdParametersCompat> for ProposedGovernanceThresholdParameters {
    fn from(value: ProposedGovernanceThresholdParametersCompat) -> Self {
        Self {
            parameters: value.parameters.into(),
            per_domain_reconstruction_thresholds: value.per_domain_thresholds,
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<ProposedGovernanceThresholdParameters> for ProposedGovernanceThresholdParametersCompat {
    fn from(value: ProposedGovernanceThresholdParameters) -> Self {
        Self {
            parameters: value.parameters.into(),
            per_domain_thresholds: value.per_domain_reconstruction_thresholds,
        }
    }
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
pub struct GovernanceThresholdParametersVotes {
    pub proposal_by_account:
        BTreeMap<AuthenticatedAccountId, ProposedGovernanceThresholdParameters>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct GovernanceThresholdParametersVotesCompat {
    pub proposal_by_account:
        BTreeMap<AuthenticatedAccountId, ProposedGovernanceThresholdParametersCompat>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<GovernanceThresholdParametersVotesCompat> for GovernanceThresholdParametersVotes {
    fn from(value: GovernanceThresholdParametersVotesCompat) -> Self {
        Self {
            proposal_by_account: value
                .proposal_by_account
                .into_iter()
                .map(|(account, proposal)| (account, proposal.into()))
                .collect(),
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<GovernanceThresholdParametersVotes> for GovernanceThresholdParametersVotesCompat {
    fn from(value: GovernanceThresholdParametersVotes) -> Self {
        Self {
            proposal_by_account: value
                .proposal_by_account
                .into_iter()
                .map(|(account, proposal)| (account, proposal.into()))
                .collect(),
        }
    }
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
    pub parameters: GovernanceThresholdParameters,
    pub instance: Option<KeyEventInstance>,
    pub next_attempt_id: AttemptId,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct KeyEventCompat {
    pub epoch_id: EpochId,
    pub domain: DomainConfig,
    pub parameters: GovernanceThresholdParametersCompat,
    pub instance: Option<KeyEventInstance>,
    pub next_attempt_id: AttemptId,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<KeyEventCompat> for KeyEvent {
    fn from(value: KeyEventCompat) -> Self {
        Self {
            epoch_id: value.epoch_id,
            domain: value.domain,
            parameters: value.parameters.into(),
            instance: value.instance,
            next_attempt_id: value.next_attempt_id,
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<KeyEvent> for KeyEventCompat {
    fn from(value: KeyEvent) -> Self {
        Self {
            epoch_id: value.epoch_id,
            domain: value.domain,
            parameters: value.parameters.into(),
            instance: value.instance,
            next_attempt_id: value.next_attempt_id,
        }
    }
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

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct InitializingContractStateCompat {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: KeyEventCompat,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<InitializingContractStateCompat> for InitializingContractState {
    fn from(value: InitializingContractStateCompat) -> Self {
        Self {
            domains: value.domains,
            epoch_id: value.epoch_id,
            generated_keys: value.generated_keys,
            generating_key: value.generating_key.into(),
            cancel_votes: value.cancel_votes,
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<InitializingContractState> for InitializingContractStateCompat {
    fn from(value: InitializingContractState) -> Self {
        Self {
            domains: value.domains,
            epoch_id: value.epoch_id,
            generated_keys: value.generated_keys,
            generating_key: value.generating_key.into(),
            cancel_votes: value.cancel_votes,
        }
    }
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
    pub parameters: GovernanceThresholdParameters,
    pub parameters_votes: GovernanceThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct RunningContractStateCompat {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: GovernanceThresholdParametersCompat,
    pub parameters_votes: GovernanceThresholdParametersVotesCompat,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<RunningContractStateCompat> for RunningContractState {
    fn from(value: RunningContractStateCompat) -> Self {
        Self {
            domains: value.domains,
            keyset: value.keyset,
            parameters: value.parameters.into(),
            parameters_votes: value.parameters_votes.into(),
            add_domains_votes: value.add_domains_votes,
            previously_cancelled_resharing_epoch_id: value.previously_cancelled_resharing_epoch_id,
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<RunningContractState> for RunningContractStateCompat {
    fn from(value: RunningContractState) -> Self {
        Self {
            domains: value.domains,
            keyset: value.keyset,
            parameters: value.parameters.into(),
            parameters_votes: value.parameters_votes.into(),
            add_domains_votes: value.add_domains_votes,
            previously_cancelled_resharing_epoch_id: value.previously_cancelled_resharing_epoch_id,
        }
    }
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
    /// Per-domain `ReconstructionThreshold` updates carried from the accepted
    /// proposal. Applied to the `DomainRegistry` when resharing completes.
    #[serde(default)]
    pub per_domain_reconstruction_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ResharingContractStateCompat {
    pub previous_running_state: RunningContractStateCompat,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEventCompat,
    pub cancellation_requests: HashSet<AuthenticatedAccountId>,
    #[serde(default)]
    pub per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<ResharingContractStateCompat> for ResharingContractState {
    fn from(value: ResharingContractStateCompat) -> Self {
        Self {
            previous_running_state: value.previous_running_state.into(),
            reshared_keys: value.reshared_keys,
            resharing_key: value.resharing_key.into(),
            cancellation_requests: value.cancellation_requests,
            per_domain_reconstruction_thresholds: value.per_domain_thresholds,
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<ResharingContractState> for ResharingContractStateCompat {
    fn from(value: ResharingContractState) -> Self {
        Self {
            previous_running_state: value.previous_running_state.into(),
            reshared_keys: value.reshared_keys,
            resharing_key: value.resharing_key.into(),
            cancellation_requests: value.cancellation_requests,
            per_domain_thresholds: value.per_domain_reconstruction_thresholds,
        }
    }
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

// TODO(XXXX): Delete this code after upgrade 3.14.0
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum ProtocolContractStateCompat {
    NotInitialized,
    Initializing(InitializingContractStateCompat),
    Running(RunningContractStateCompat),
    Resharing(ResharingContractStateCompat),
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<ProtocolContractStateCompat> for ProtocolContractState {
    fn from(value: ProtocolContractStateCompat) -> Self {
        match value {
            ProtocolContractStateCompat::NotInitialized => Self::NotInitialized,
            ProtocolContractStateCompat::Initializing(state) => Self::Initializing(state.into()),
            ProtocolContractStateCompat::Running(state) => Self::Running(state.into()),
            ProtocolContractStateCompat::Resharing(state) => Self::Resharing(state.into()),
        }
    }
}

// TODO(XXXX): Delete this code after upgrade 3.14.0
impl From<ProtocolContractState> for ProtocolContractStateCompat {
    fn from(value: ProtocolContractState) -> Self {
        match value {
            ProtocolContractState::NotInitialized => Self::NotInitialized,
            ProtocolContractState::Initializing(state) => Self::Initializing(state.into()),
            ProtocolContractState::Running(state) => Self::Running(state.into()),
            ProtocolContractState::Resharing(state) => Self::Resharing(state.into()),
        }
    }
}

fn params_to_string(output: &mut String, parameters: &GovernanceThresholdParameters) {
    output.push_str("    Participants:\n");
    for (account_id, id, info) in &parameters.participants.participants {
        output.push_str(&format!("      ID {}: {} ({})\n", id, account_id, info.url));
    }
    output.push_str(&format!(
        "    GovernanceThreshold: {}\n",
        parameters.governance_threshold.value()
    ));
}

/// Formats the protocol state for human-readable display.
///
/// This does not calculate automatic timeouts for key generation or resharing
/// attempts; an instance is reported as "active" whenever `instance` is
/// populated, regardless of whether it would be considered timed out on-chain.
pub fn protocol_state_to_string(contract_state: &ProtocolContractState) -> String {
    let mut output = String::new();
    match contract_state {
        ProtocolContractState::NotInitialized => {
            output.push_str("Contract is not initialized\n");
        }
        ProtocolContractState::Initializing(state) => {
            output.push_str("Contract is in Initializing state (key generation)");
            output.push_str(&format!("  Epoch: {}\n", state.generating_key.epoch_id));
            output.push_str("  Domains:\n");
            for (i, domain) in state.domains.domains.iter().enumerate() {
                output.push_str(&format!(
                    "    Domain {}: {:?}, ",
                    domain.id,
                    Curve::from(domain.protocol),
                ));
                #[expect(clippy::comparison_chain)]
                if i < state.generated_keys.len() {
                    output.push_str(&format!(
                        "key generated (attempt ID {})\n",
                        state.generated_keys[i].attempt
                    ));
                } else if i == state.generated_keys.len() {
                    output.push_str("generating key: ");
                    if let Some(instance) = state.generating_key.instance.as_ref() {
                        output.push_str(&format!(
                            "active; current attempt ID: {}\n",
                            instance.attempt_id
                        ));
                    } else {
                        output.push_str(&format!(
                            "not active; next attempt ID: {}\n",
                            state.generating_key.next_attempt_id
                        ));
                    }
                } else {
                    output.push_str("queued for generation\n");
                }
            }
            output.push_str("  Parameters:\n");
            params_to_string(&mut output, &state.generating_key.parameters);
            output.push_str("  Warning: this tool does not calculate automatic timeouts for key generation attempts\n");
        }
        ProtocolContractState::Running(state) => {
            output.push_str("Contract is in Running state\n");
            output.push_str(&format!("  Epoch: {}\n", state.keyset.epoch_id));
            output.push_str("  Keyset:\n");
            for (domain, key) in state
                .domains
                .domains
                .iter()
                .zip(state.keyset.domains.iter())
            {
                output.push_str(&format!(
                    "    Domain {}: {:?}, key from attempt {}\n",
                    domain.id,
                    Curve::from(domain.protocol),
                    key.attempt
                ));
            }
            output.push_str("  Parameters:\n");
            params_to_string(&mut output, &state.parameters);
        }
        ProtocolContractState::Resharing(state) => {
            output.push_str("Contract is in Resharing state\n");
            output.push_str(&format!(
                "  Epoch transition: original {} --> prospective {}\n",
                state.previous_running_state.keyset.epoch_id, state.resharing_key.epoch_id,
            ));
            output.push_str("  Domains:\n");
            for (i, domain) in state
                .previous_running_state
                .domains
                .domains
                .iter()
                .enumerate()
            {
                output.push_str(&format!(
                    "    Domain {}: {:?}, original key from attempt {}, ",
                    domain.id,
                    Curve::from(domain.protocol),
                    state.previous_running_state.keyset.domains[i].attempt
                ));

                #[expect(clippy::comparison_chain)]
                if i < state.reshared_keys.len() {
                    output.push_str(&format!(
                        "reshared (attempt ID {})\n",
                        state.reshared_keys[i].attempt
                    ));
                } else if i == state.reshared_keys.len() {
                    output.push_str("resharing key: ");
                    if let Some(instance) = state.resharing_key.instance.as_ref() {
                        output.push_str(&format!(
                            "active; current attempt ID: {}\n",
                            instance.attempt_id
                        ));
                    } else {
                        output.push_str(&format!(
                            "not active; next attempt ID: {}\n",
                            state.resharing_key.next_attempt_id
                        ));
                    }
                } else {
                    output.push_str("queued for resharing\n");
                }
            }
            output.push_str("  Previous Parameters:\n");
            params_to_string(&mut output, &state.previous_running_state.parameters);
            output.push_str("  Proposed Parameters:\n");
            params_to_string(&mut output, &state.resharing_key.parameters);

            output.push_str("  Warning: this tool does not calculate automatic timeouts for resharing attempts\n");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::participants::{ParticipantId, ParticipantInfo};

    #[test]
    fn test_protocol_state_serialization() {
        let state = ProtocolContractState::NotInitialized;
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("NotInitialized"));
    }

    #[test]
    #[expect(non_snake_case)]
    fn protocol_state_to_string__should_describe_not_initialized_state() {
        // Given
        let state = ProtocolContractState::NotInitialized;

        // When
        let output = protocol_state_to_string(&state);

        // Then
        assert_eq!(output, "Contract is not initialized\n");
    }

    fn sample_participants() -> Participants {
        Participants {
            next_id: ParticipantId(1),
            participants: vec![(
                "alice.near".parse().unwrap(),
                ParticipantId(0),
                ParticipantInfo {
                    url: "https://alice.com".to_string(),
                    tls_public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
                        .parse()
                        .unwrap(),
                },
            )],
        }
    }

    #[test]
    #[expect(non_snake_case)]
    fn proposed_threshold_parameters__handles_current_proposal_payload() {
        // Given
        let participants = sample_participants();
        let proposal = serde_json::to_value(ProposedGovernanceThresholdParametersCompat {
            parameters: GovernanceThresholdParametersCompat {
                participants,
                threshold: GovernanceThreshold::new(1),
            },
            per_domain_thresholds: BTreeMap::from([(DomainId(0), ReconstructionThreshold::new(1))]),
        })
        .unwrap();

        // When
        let parsed: ProposedGovernanceThresholdParametersCompat =
            serde_json::from_value(proposal).unwrap();

        // Then
        assert_eq!(parsed.per_domain_thresholds.len(), 1);
    }

    #[test]
    #[expect(non_snake_case)]
    fn proposed_threshold_parameters__handles_current_proposal_payload_empty_per_domain_thresholds()
    {
        // Given
        let participants = sample_participants();
        let proposal = serde_json::from_value(serde_json::json!( {
            "parameters": {
                "participants": participants,
        "threshold": GovernanceThreshold::new(1),
            }
        }))
        .unwrap();

        // When
        let parsed: ProposedGovernanceThresholdParametersCompat =
            serde_json::from_value(proposal).unwrap();

        // Then
        assert_eq!(parsed.per_domain_thresholds.len(), 0);
    }
}
