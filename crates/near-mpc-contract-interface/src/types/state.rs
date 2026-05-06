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

pub use mpc_primitives::{AttemptId, EpochId, ReconstructionThreshold, Threshold};

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
#[serde(from = "DomainConfigCompat")]
pub struct DomainConfig {
    pub id: DomainId,
    pub curve: Curve,
    pub protocol: Protocol,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub purpose: DomainPurpose,
}

// TODO(#3166): once every deployment has run the v3.9.1 migration, the
// legacy-JSON compat below can be removed entirely. After that point `state()`
// always emits `protocol` and `reconstruction_threshold`, so the
// `DomainConfig` struct can derive `Deserialize` directly and the following
// items become dead code:
//   - `DomainConfigCompat` and its `From<DomainConfigCompat>` impl
//   - `infer_protocol`
//   - `RawDomainConfig`, `RawDomainRegistry`, `RawAddDomainsVotes`
//   - `RunningContractStateCompat`, `KeyEventCompat`,
//     `InitializingContractStateCompat` (and their `serde(from = …)` attrs)
/// Standalone-deserialization compat: `protocol` is optional (inferred from
/// `curve` for legacy JSON); `reconstruction_threshold` is required.
/// Legacy `state()` reads back-fill the threshold one level up via
/// `RawDomainConfig`, not here.
#[derive(Deserialize)]
struct DomainConfigCompat {
    id: DomainId,
    curve: Curve,
    protocol: Option<Protocol>,
    reconstruction_threshold: ReconstructionThreshold,
    purpose: DomainPurpose,
}

impl From<DomainConfigCompat> for DomainConfig {
    fn from(c: DomainConfigCompat) -> Self {
        Self {
            id: c.id,
            curve: c.curve,
            protocol: c.protocol.unwrap_or_else(|| infer_protocol(c.curve)),
            reconstruction_threshold: c.reconstruction_threshold,
            purpose: c.purpose,
        }
    }
}

/// Legacy curves map 1:1 to protocols (DamgardEtAl never appeared in old JSON).
fn infer_protocol(curve: Curve) -> Protocol {
    match curve {
        Curve::Secp256k1 => Protocol::CaitSith,
        Curve::Edwards25519 => Protocol::Frost,
        Curve::Bls12381 => Protocol::ConfidentialKeyDerivation,
    }
}

/// Intermediate for legacy `state()` reads where `reconstruction_threshold`
/// may be absent and is filled from the surrounding `parameters.threshold`.
#[derive(Deserialize)]
struct RawDomainConfig {
    id: DomainId,
    curve: Curve,
    protocol: Option<Protocol>,
    reconstruction_threshold: Option<ReconstructionThreshold>,
    purpose: DomainPurpose,
}

impl RawDomainConfig {
    fn into_domain_config(self, fallback: ReconstructionThreshold) -> DomainConfig {
        DomainConfig {
            id: self.id,
            curve: self.curve,
            protocol: self.protocol.unwrap_or_else(|| infer_protocol(self.curve)),
            reconstruction_threshold: self.reconstruction_threshold.unwrap_or(fallback),
            purpose: self.purpose,
        }
    }
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
#[serde(from = "KeyEventCompat")]
pub struct KeyEvent {
    pub epoch_id: EpochId,
    pub domain: DomainConfig,
    pub parameters: ThresholdParameters,
    pub instance: Option<KeyEventInstance>,
    pub next_attempt_id: AttemptId,
}

/// Legacy compat: back-fill the embedded domain's `reconstruction_threshold`
/// from the event's own `parameters.threshold`.
#[derive(Deserialize)]
struct KeyEventCompat {
    epoch_id: EpochId,
    domain: RawDomainConfig,
    parameters: ThresholdParameters,
    instance: Option<KeyEventInstance>,
    next_attempt_id: AttemptId,
}

impl From<KeyEventCompat> for KeyEvent {
    fn from(c: KeyEventCompat) -> Self {
        let fallback = ReconstructionThreshold::from(c.parameters.threshold);
        Self {
            epoch_id: c.epoch_id,
            domain: c.domain.into_domain_config(fallback),
            parameters: c.parameters,
            instance: c.instance,
            next_attempt_id: c.next_attempt_id,
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
#[serde(from = "InitializingContractStateCompat")]
pub struct InitializingContractState {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: KeyEvent,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

/// Legacy compat: back-fill registry thresholds from
/// `generating_key.parameters.threshold` (the global threshold under which
/// keygen was started, shared by every domain in the legacy registry).
#[derive(Deserialize)]
struct InitializingContractStateCompat {
    domains: RawDomainRegistry,
    epoch_id: EpochId,
    generated_keys: Vec<KeyForDomain>,
    generating_key: KeyEvent,
    cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

impl From<InitializingContractStateCompat> for InitializingContractState {
    fn from(c: InitializingContractStateCompat) -> Self {
        let fallback = ReconstructionThreshold::from(c.generating_key.parameters.threshold);
        Self {
            domains: DomainRegistry {
                domains: c
                    .domains
                    .domains
                    .into_iter()
                    .map(|d| d.into_domain_config(fallback))
                    .collect(),
                next_domain_id: c.domains.next_domain_id,
            },
            epoch_id: c.epoch_id,
            generated_keys: c.generated_keys,
            generating_key: c.generating_key,
            cancel_votes: c.cancel_votes,
        }
    }
}

/// State when the contract is ready for signature operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
#[serde(from = "RunningContractStateCompat")]
pub struct RunningContractState {
    pub domains: DomainRegistry,
    pub keyset: Keyset,
    pub parameters: ThresholdParameters,
    pub parameters_votes: ThresholdParametersVotes,
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

/// Legacy compat: back-fill per-domain `reconstruction_threshold` from the
/// global `parameters.threshold`. Also covers proposals nested in
/// `add_domains_votes`.
#[derive(Deserialize)]
struct RunningContractStateCompat {
    domains: RawDomainRegistry,
    keyset: Keyset,
    parameters: ThresholdParameters,
    parameters_votes: ThresholdParametersVotes,
    add_domains_votes: RawAddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

#[derive(Deserialize)]
struct RawDomainRegistry {
    domains: Vec<RawDomainConfig>,
    next_domain_id: u64,
}

#[derive(Deserialize)]
struct RawAddDomainsVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<RawDomainConfig>>,
}

impl From<RunningContractStateCompat> for RunningContractState {
    fn from(c: RunningContractStateCompat) -> Self {
        let fallback = ReconstructionThreshold::from(c.parameters.threshold);
        Self {
            domains: DomainRegistry {
                domains: c
                    .domains
                    .domains
                    .into_iter()
                    .map(|d| d.into_domain_config(fallback))
                    .collect(),
                next_domain_id: c.domains.next_domain_id,
            },
            keyset: c.keyset,
            parameters: c.parameters,
            parameters_votes: c.parameters_votes,
            add_domains_votes: AddDomainsVotes {
                proposal_by_account: c
                    .add_domains_votes
                    .proposal_by_account
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            v.into_iter()
                                .map(|d| d.into_domain_config(fallback))
                                .collect(),
                        )
                    })
                    .collect(),
            },
            previously_cancelled_resharing_epoch_id: c.previously_cancelled_resharing_epoch_id,
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

fn params_to_string(output: &mut String, parameters: &ThresholdParameters) {
    output.push_str("    Participants:\n");
    for (account_id, id, info) in &parameters.participants.participants {
        output.push_str(&format!("      ID {}: {} ({})\n", id, account_id, info.url));
    }
    output.push_str(&format!(
        "    Threshold: {}\n",
        parameters.threshold.value()
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
                output.push_str(&format!("    Domain {}: {:?}, ", domain.id, domain.curve));
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
                    domain.id, domain.curve, key.attempt
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
                    domain.id, domain.curve, state.previous_running_state.keyset.domains[i].attempt
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

    /// Bare-bones legacy `state()` JSON without per-domain
    /// `reconstruction_threshold`. Mirrors what a not-yet-upgraded contract
    /// would emit. Both `Running` and `Initializing` shapes need to keep
    /// deserializing with the field back-filled from the surrounding
    /// `parameters.threshold`.
    fn legacy_running_state_json() -> &'static str {
        r#"{
            "domains": {
                "domains": [
                    {"id": 0, "curve": "Secp256k1", "purpose": "Sign"},
                    {"id": 1, "curve": "Edwards25519", "purpose": "Sign"}
                ],
                "next_domain_id": 2
            },
            "keyset": { "epoch_id": 0, "domains": [] },
            "parameters": {
                "participants": { "next_id": 0, "participants": [] },
                "threshold": 5
            },
            "parameters_votes": { "proposal_by_account": {} },
            "add_domains_votes": { "proposal_by_account": {} },
            "previously_cancelled_resharing_epoch_id": null
        }"#
    }

    #[test]
    #[expect(non_snake_case)]
    fn running_state_compat__should_backfill_missing_reconstruction_threshold() {
        // Given legacy `state()` JSON with no per-domain reconstruction_threshold
        let json = legacy_running_state_json();

        // When deserializing into the new RunningContractState DTO
        let state: RunningContractState = serde_json::from_str(json).unwrap();

        // Then each domain inherits the global threshold (5)
        let expected = ReconstructionThreshold::new(5);
        assert_eq!(state.parameters.threshold, Threshold::new(5));
        assert_eq!(state.domains.domains.len(), 2);
        for domain in &state.domains.domains {
            assert_eq!(domain.reconstruction_threshold, expected);
        }
    }

    #[test]
    #[expect(non_snake_case)]
    fn domain_config__should_require_reconstruction_threshold_directly() {
        // Given JSON missing reconstruction_threshold (e.g. an old vote_add_domains payload)
        let bad = r#"{"id":0,"curve":"Secp256k1","purpose":"Sign"}"#;

        // When deserializing as a standalone DomainConfig
        let result: Result<DomainConfig, _> = serde_json::from_str(bad);

        // Then it is rejected — the standalone path is not the place to back-fill
        assert!(
            result.is_err(),
            "Standalone DomainConfig must require reconstruction_threshold"
        );
    }
}
