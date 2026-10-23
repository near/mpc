//! DTO types for protocol contract state.
//!
//! These types mirror the internal contract state types and are used for JSON serialization
//! in the contract's public API (e.g., the `state()` view function).

use crate::types::PublicKeyExtended;
use crate::types::participants::{ParticipantId, Participants};
use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::hash::ProposalHash;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

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
    pub threshold: GovernanceThreshold,
}

/// A proposed set of threshold parameters submitted to `vote_new_parameters`:
/// the proposed [`GovernanceThresholdParameters`] plus per-domain [`ReconstructionThreshold`]
/// updates for the resharing it would trigger. An empty `per_domain_thresholds`
/// keeps the current ones; a populated map must reference only existing domains
/// (contract-validated), is applied to the [`DomainRegistry`] on resharing, and
/// never persists onto the stored [`GovernanceThresholdParameters`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ProposedGovernanceThresholdParameters {
    pub parameters: GovernanceThresholdParameters,
    #[serde(default)]
    pub per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
}

// =============================================================================
// Voting Types
// =============================================================================

/// Voters grouped by the [`ProposalHash`] of the [`ProposedGovernanceThresholdParameters`]
/// they voted for.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Deref,
)]
#[serde(transparent)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct GovernanceThresholdParametersVotes(
    pub BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>>,
);

/// Also accepts the pre-tally report (`{"proposal_by_account": {...}}`) of contracts that
/// still store full proposals, so a newer reader can follow an older contract across an upgrade.
impl<'de> Deserialize<'de> for GovernanceThresholdParametersVotes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Tally(BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>>),
            // TODO(#XXXX): drop once the 3.18 contract is deployed and nodes are upgraded; a plain
            // derive(Deserialize) then suffices.
            Legacy {
                proposal_by_account:
                    BTreeMap<AuthenticatedAccountId, ProposedGovernanceThresholdParameters>,
            },
        }
        Ok(Self(match Repr::deserialize(deserializer)? {
            Repr::Tally(tally) => tally,
            Repr::Legacy {
                proposal_by_account,
            } => tally_by_proposal_hash(proposal_by_account),
        }))
    }
}

/// Groups per-voter proposals by the hash the contract stores for them: SHA-256 of the
/// Borsh encoding, which the DTOs share with the contract types.
pub(crate) fn tally_by_proposal_hash<V: Ord, P: BorshSerialize>(
    proposal_by_voter: BTreeMap<V, P>,
) -> BTreeMap<ProposalHash, BTreeSet<V>> {
    let mut tally: BTreeMap<ProposalHash, BTreeSet<V>> = BTreeMap::new();
    for (voter, proposal) in proposal_by_voter {
        let bytes = borsh::to_vec(&proposal).expect("borsh serialization must succeed");
        let hash = ProposalHash::new(sha2::Sha256::digest(bytes).into());
        tally.entry(hash).or_default().insert(voter);
    }
    tally
}

/// Voters grouped by the [`ProposalHash`] of the [`DomainConfig`] list they voted to add.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Deref,
)]
#[serde(transparent)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AddDomainsVotes(pub BTreeMap<ProposalHash, BTreeSet<AuthenticatedParticipantId>>);

/// Also accepts the pre-tally report (`{"proposal_by_account": {...}}`) of contracts that
/// still store full domain lists; see [`GovernanceThresholdParametersVotes`].
impl<'de> Deserialize<'de> for AddDomainsVotes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Tally(BTreeMap<ProposalHash, BTreeSet<AuthenticatedParticipantId>>),
            // TODO(#XXXX): drop once the 3.18 contract is deployed and nodes are upgraded.
            // Keys stay strings in the untagged buffer, so the participant id is parsed below.
            Legacy {
                proposal_by_account: BTreeMap<String, Vec<DomainConfig>>,
            },
        }
        Ok(Self(match Repr::deserialize(deserializer)? {
            Repr::Tally(tally) => tally,
            Repr::Legacy {
                proposal_by_account,
            } => {
                let proposal_by_account = proposal_by_account
                    .into_iter()
                    .map(|(voter, domains)| {
                        let id = voter.parse().map_err(serde::de::Error::custom)?;
                        Ok((AuthenticatedParticipantId(ParticipantId(id)), domains))
                    })
                    .collect::<Result<BTreeMap<_, _>, D::Error>>()?;
                tally_by_proposal_hash(proposal_by_account)
            }
        }))
    }
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
    pub parameters: GovernanceThresholdParameters,
    pub parameters_votes: GovernanceThresholdParametersVotes,
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
    /// The state being reshared from; while resharing, its `parameters_votes` hold the
    /// re-proposal votes for the prospective epoch.
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
    pub cancellation_requests: BTreeSet<AuthenticatedAccountId>,
    /// Per-domain [`ReconstructionThreshold`] updates carried from the accepted
    /// proposal. Applied to the [`DomainRegistry`] when resharing completes.
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

fn params_to_string(output: &mut String, parameters: &GovernanceThresholdParameters) {
    output.push_str("    Participants:\n");
    for (account_id, id, info) in &parameters.participants.participants {
        output.push_str(&format!("      ID {}: {} ({})\n", id, account_id, info.url));
    }
    output.push_str(&format!(
        "    GovernanceThreshold: {}\n",
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

    fn sample_participants() -> Participants {
        Participants {
            next_id: ParticipantId(1),
            participants: vec![(
                "alice.near".parse().unwrap(),
                ParticipantId(0),
                ParticipantInfo {
                    url: "https://alice.com".try_into().unwrap(),
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
        let proposal = serde_json::to_value(ProposedGovernanceThresholdParameters {
            parameters: GovernanceThresholdParameters {
                participants,
                threshold: GovernanceThreshold::new(1),
            },
            per_domain_thresholds: BTreeMap::from([(DomainId(0), ReconstructionThreshold::new(1))]),
        })
        .unwrap();

        // When
        let parsed: ProposedGovernanceThresholdParameters =
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
        let parsed: ProposedGovernanceThresholdParameters =
            serde_json::from_value(proposal).unwrap();

        // Then
        assert_eq!(parsed.per_domain_thresholds.len(), 0);
    }

    #[test]
    fn parameters_votes_serialize_as_a_transparent_map_keyed_by_proposal_hash() {
        // Given
        let proposal = ProposalHash::new([0xCD; 32]);
        let votes = GovernanceThresholdParametersVotes(BTreeMap::from([(
            proposal,
            BTreeSet::from([AuthenticatedAccountId("alice.near".parse().unwrap())]),
        )]));

        // When
        let json = serde_json::to_value(&votes).unwrap();

        // Then
        assert_eq!(json[proposal.as_hex()][0], "alice.near");
    }

    #[test]
    fn parameters_votes_deserialize_the_legacy_empty_report() {
        let votes: super::GovernanceThresholdParametersVotes =
            serde_json::from_str(r#"{"proposal_by_account":{}}"#).unwrap();

        assert_eq!(votes, super::GovernanceThresholdParametersVotes::default());
    }

    #[test]
    fn parameters_votes_roundtrip_the_tally() {
        let votes =
            super::GovernanceThresholdParametersVotes(std::collections::BTreeMap::from([(
                mpc_primitives::hash::ProposalHash::new([7u8; 32]),
                std::collections::BTreeSet::from([super::AuthenticatedAccountId(
                    "alice.near".parse().unwrap(),
                )]),
            )]));

        let json = serde_json::to_string(&votes).unwrap();

        assert_eq!(
            serde_json::from_str::<super::GovernanceThresholdParametersVotes>(&json).unwrap(),
            votes
        );
    }

    #[test]
    fn add_domains_votes_deserialize_the_legacy_empty_report() {
        let votes: super::AddDomainsVotes =
            serde_json::from_str(r#"{"proposal_by_account":{}}"#).unwrap();

        assert_eq!(votes, super::AddDomainsVotes::default());
    }

    #[test]
    fn add_domains_votes_roundtrip_the_tally() {
        let votes = super::AddDomainsVotes(std::collections::BTreeMap::from([(
            mpc_primitives::hash::ProposalHash::new([7u8; 32]),
            std::collections::BTreeSet::from([super::AuthenticatedParticipantId(
                crate::types::participants::ParticipantId(3),
            )]),
        )]));

        let json = serde_json::to_string(&votes).unwrap();

        assert_eq!(
            serde_json::from_str::<super::AddDomainsVotes>(&json).unwrap(),
            votes
        );
    }
}
