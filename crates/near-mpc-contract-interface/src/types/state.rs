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
// Threshold/Participants Types
// =============================================================================

/// Threshold parameters for distributed key operations: the current
/// participant set and the governance threshold. This is the stored,
/// always-current shape; per-domain reconstruction-threshold *proposals* live
/// on [`ProposedThresholdParameters`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ThresholdParameters {
    pub participants: Participants,
    pub threshold: Threshold,
}

/// A proposed set of threshold parameters submitted to `vote_new_parameters`.
/// Carries the proposed [`ThresholdParameters`] (participant set and threshold)
/// plus an optional per-domain `ReconstructionThreshold` overlay for the
/// resharing it would trigger.
//
// `per_domain_thresholds` proposes an updated `ReconstructionThreshold` for the
// listed domains. An empty map means "keep current per-domain thresholds"; a
// populated map must reference only existing domains (validated by the
// contract). The overlay is applied to the `DomainRegistry` when resharing
// completes and never persists onto the stored `ThresholdParameters`.
//
// ## Wire contract and the `serde(flatten)` migration path
//
// The frozen wire contract is the flat object `{ participants, threshold,
// per_domain_thresholds }` (and the positional borsh layout `[participants,
// threshold, per_domain_thresholds]`). `serde(flatten)` is merely *how* that
// flat JSON is produced today — by reusing `ThresholdParameters` as a named
// sub-field — and is an implementation detail, not part of the contract.
// `serde(default)` parses a payload lacking `per_domain_thresholds` as empty,
// so pre-3.11 callers keep submitting `{ participants, threshold }` unchanged.
//
// To drop `serde(flatten)` later (e.g. after 3.12, to allow
// `#[serde(deny_unknown_fields)]` or to escape flatten's `Content`-buffering
// quirks), inline the two `parameters` fields:
//
//     pub participants: Participants,
//     pub threshold: Threshold,
//     #[serde(default)]
//     pub per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
//
// That is byte-identical for JSON, borsh, and the generated ABI: borsh is
// positional and ignores serde attributes, and the inlined JSON keys match. So
// it needs no compat struct and no migration — only the conversion impls in
// `dto_mapping.rs` that read `.parameters` must follow the field move. The
// `proposed_threshold_parameters__*` wire-lock tests below pin this shape so a
// non-equivalent change fails loudly. Changing the *shape itself* (e.g. nesting
// the params under a `parameters` key) WOULD be wire-breaking and would instead
// require a compat deserializer accepting both the old flat and new nested
// forms across a transition window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ProposedThresholdParameters {
    #[serde(flatten)]
    pub parameters: ThresholdParameters,
    #[serde(default)]
    pub per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
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
    pub proposal_by_account: BTreeMap<AuthenticatedAccountId, ProposedThresholdParameters>,
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
    /// Per-domain `ReconstructionThreshold` overlay carried from the accepted
    /// proposal. Applied to the `DomainRegistry` when resharing completes.
    #[serde(default)]
    pub per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
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

    /// A proposal carrying a non-empty per-domain overlay, used by the
    /// `ProposedThresholdParameters` wire-lock tests.
    fn sample_proposal() -> ProposedThresholdParameters {
        let participants = Participants {
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
        };
        ProposedThresholdParameters {
            parameters: ThresholdParameters {
                participants,
                threshold: Threshold::new(1),
            },
            per_domain_thresholds: BTreeMap::from([(DomainId(0), ReconstructionThreshold::new(1))]),
        }
    }

    /// Wire-format lock: the public contract for `ProposedThresholdParameters` is
    /// the flat JSON object `{ participants, threshold, per_domain_thresholds }`,
    /// not the `#[serde(flatten)]` mechanism that currently produces it. Pinning
    /// the shape here means dropping `flatten` later (by inlining the `parameters`
    /// fields) can be proven byte-identical rather than taken on faith.
    #[test]
    #[expect(non_snake_case)]
    fn proposed_threshold_parameters__serializes_to_flat_keys() {
        // Given a proposal carrying a non-empty per-domain overlay.
        let proposal = sample_proposal();

        // When serialized to JSON.
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&proposal).unwrap()).unwrap();

        // Then the object is flat: `participants`/`threshold` sit at the top level
        // alongside `per_domain_thresholds`, with no nested `parameters` key.
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["participants", "per_domain_thresholds", "threshold"]);
    }

    /// Pre-3.11 callers submit `{ participants, threshold }` with no
    /// `per_domain_thresholds`. `serde(default)` must keep parsing that as an
    /// empty (no-change) overlay — the backward-compat guarantee that let the
    /// field be added without a wire break.
    #[test]
    #[expect(non_snake_case)]
    fn proposed_threshold_parameters__legacy_payload_omitting_overlay__parses_as_empty() {
        // Given a legacy proposal value with the overlay field absent.
        let mut legacy = serde_json::to_value(sample_proposal()).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("per_domain_thresholds");

        // When deserialized.
        let parsed: ProposedThresholdParameters = serde_json::from_value(legacy).unwrap();

        // Then the overlay defaults to empty.
        assert!(parsed.per_domain_thresholds.is_empty());
    }

    /// borsh is positional and ignores serde attributes, so the stored layout is
    /// `[participants, threshold, per_domain_thresholds]` regardless of `flatten`.
    /// A round-trip locks that the type stays borsh-stable across the eventual
    /// inlining.
    #[test]
    #[expect(non_snake_case)]
    fn proposed_threshold_parameters__borsh_round_trips() {
        // Given a proposal carrying a non-empty per-domain overlay.
        let proposal = sample_proposal();

        // When borsh round-tripped.
        let bytes = borsh::to_vec(&proposal).unwrap();
        let decoded: ProposedThresholdParameters = borsh::from_slice(&bytes).unwrap();

        // Then it survives unchanged.
        assert_eq!(decoded, proposal);
    }
}
