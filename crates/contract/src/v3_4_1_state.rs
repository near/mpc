//! ## Overview
//! This module stores the previous contract state-the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::{BTreeMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types as dtos;
use near_sdk::{env, store::LookupMap};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{infer_purpose_from_scheme, SignatureScheme},
        key_state::{
            AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain, Keyset,
        },
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
        votes::ThresholdParametersVotes,
    },
    state::{initializing::InitializingContractState, key_event::KeyEvent},
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, StaleData, StorageKey,
};

/// The contract state layout of the current production contract.
/// This does not have `pending_verify_foreign_tx_requests` or `domain_purposes`.
/// `DomainConfig` does not have a `purpose` field.
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
    stale_data: StaleData,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

/// Legacy `DomainConfig` without a `purpose` field.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct DomainConfig {
    pub(crate) id: crate::primitives::domain::DomainId,
    pub(crate) scheme: SignatureScheme,
}

/// Legacy `DomainRegistry` containing `Vec<DomainConfig>` without purposes.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct DomainRegistry {
    domains: Vec<DomainConfig>,
    next_domain_id: u64,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct RunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: ThresholdParameters,
    parameters_votes: ThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ResharingContractState {
    previous_running_state: RunningContractState,
    reshared_keys: Vec<KeyForDomain>,
    resharing_key: KeyEvent,
    cancellation_requests: HashSet<AuthenticatedAccountId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct AddDomainsVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<DomainConfig>>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let protocol_state: crate::state::ProtocolContractState = value.protocol_state.into();

        let crate::state::ProtocolContractState::Running(_running_state) = &protocol_state else {
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
            stale_data: crate::StaleData {},
        }
    }
}

impl From<ProtocolContractState> for crate::state::ProtocolContractState {
    fn from(value: ProtocolContractState) -> Self {
        match value {
            ProtocolContractState::NotInitialized => Self::NotInitialized,
            ProtocolContractState::Initializing(state) => Self::Initializing(state),
            ProtocolContractState::Running(state) => Self::Running(state.into()),
            ProtocolContractState::Resharing(state) => Self::Resharing(state.into()),
        }
    }
}

impl From<DomainConfig> for crate::primitives::domain::DomainConfig {
    fn from(value: DomainConfig) -> Self {
        Self {
            id: value.id,
            scheme: value.scheme,
            purpose: infer_purpose_from_scheme(value.scheme),
        }
    }
}

impl From<DomainRegistry> for crate::primitives::domain::DomainRegistry {
    fn from(value: DomainRegistry) -> Self {
        let domains: Vec<crate::primitives::domain::DomainConfig> =
            value.domains.into_iter().map(Into::into).collect();
        // Safe: the legacy registry was valid, and adding purpose doesn't affect ID ordering.
        Self::from_raw_validated(domains, value.next_domain_id)
            .expect("legacy DomainRegistry should be valid")
    }
}

impl From<RunningContractState> for crate::state::running::RunningContractState {
    fn from(value: RunningContractState) -> Self {
        Self {
            domains: value.domains.into(),
            keyset: value.keyset,
            parameters: value.parameters,
            parameters_votes: value.parameters_votes,
            add_domains_votes: value.add_domains_votes.into(),
            previously_cancelled_resharing_epoch_id: value.previously_cancelled_resharing_epoch_id,
        }
    }
}

impl From<ResharingContractState> for crate::state::resharing::ResharingContractState {
    fn from(value: ResharingContractState) -> Self {
        Self {
            previous_running_state: value.previous_running_state.into(),
            reshared_keys: value.reshared_keys,
            resharing_key: value.resharing_key,
            cancellation_requests: value.cancellation_requests,
        }
    }
}

impl From<AddDomainsVotes> for crate::primitives::domain::AddDomainsVotes {
    fn from(value: AddDomainsVotes) -> Self {
        let proposal_by_account = value
            .proposal_by_account
            .into_iter()
            .map(|(participant, proposed_domains)| {
                let proposal = proposed_domains.into_iter().map(Into::into).collect();
                (participant, proposal)
            })
            .collect();

        Self {
            proposal_by_account,
        }
    }
}

/// Convert new `DomainRegistry` back to legacy format (for tests).
#[cfg(test)]
impl From<crate::primitives::domain::DomainRegistry> for DomainRegistry {
    fn from(value: crate::primitives::domain::DomainRegistry) -> Self {
        Self {
            domains: value
                .domains()
                .iter()
                .map(|d| DomainConfig {
                    id: d.id,
                    scheme: d.scheme,
                })
                .collect(),
            next_domain_id: value.next_domain_id(),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use borsh::{to_vec, BorshDeserialize};
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    use super::{AddDomainsVotes, ProtocolContractState, RunningContractState};
    use crate::primitives::{
        domain::infer_purpose_from_scheme, key_state::AuthenticatedParticipantId,
        test_utils::gen_legacy_domains_to_add,
    };
    use crate::state::test_utils::gen_running_state;

    #[test]
    fn legacy_running_state__should_decode_and_preserve_domain_votes_during_migration() {
        // Given
        let running = gen_running_state(2);
        let first_participant_account = running.parameters.participants().participants()[0]
            .0
            .clone();

        let mut context = VMContextBuilder::new();
        context.signer_account_id(first_participant_account);
        testing_env!(context.build());

        let participant =
            AuthenticatedParticipantId::new(running.parameters.participants()).unwrap();
        let proposed_domains = gen_legacy_domains_to_add(&running.domains, 2);
        let expected_domains_with_purpose: Vec<crate::primitives::domain::DomainConfig> =
            proposed_domains
                .iter()
                .map(|domain| crate::primitives::domain::DomainConfig {
                    id: domain.id,
                    scheme: domain.scheme,
                    purpose: infer_purpose_from_scheme(domain.scheme),
                })
                .collect();

        let legacy_domains: super::DomainRegistry = running.domains.clone().into();

        let legacy_protocol_state = ProtocolContractState::Running(RunningContractState {
            domains: legacy_domains,
            keyset: running.keyset.clone(),
            parameters: running.parameters.clone(),
            parameters_votes: running.parameters_votes.clone(),
            add_domains_votes: AddDomainsVotes {
                proposal_by_account: BTreeMap::from([(participant, proposed_domains)]),
            },
            previously_cancelled_resharing_epoch_id: running
                .previously_cancelled_resharing_epoch_id,
        });

        // When
        let serialized = to_vec(&legacy_protocol_state).unwrap();
        let decoded_legacy = ProtocolContractState::try_from_slice(&serialized).unwrap();
        let crate::state::ProtocolContractState::Running(migrated_running) = decoded_legacy.into()
        else {
            panic!("expected running state");
        };

        // Then
        // Current-state decode fails on legacy payloads (missing `purpose` field in DomainConfig).
        let _ = crate::state::ProtocolContractState::try_from_slice(&serialized).unwrap_err();

        let migrated_vote = migrated_running
            .add_domains_votes
            .proposal_by_account
            .values()
            .next()
            .unwrap();
        assert_eq!(migrated_vote, &expected_domains_with_purpose);
    }
}
