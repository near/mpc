//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
};

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{
    self as dtos, CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, env,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedAccountId, EpochId, KeyForDomain, Keyset},
        participants::Participants,
        threshold_votes::GovernanceThresholdParametersVotes,
        thresholds::{GovernanceThresholdParameters, ProposedGovernanceThresholdParameters},
    },
    state::{
        ProtocolContractState, initializing::InitializingContractState, key_event::KeyEvent,
        running::RunningContractState,
    },
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ContractUpdateVotes,
};

/// Shadow of the `3.18.0` `GovernanceThresholdParametersVotes` layout.
// TODO(#4984): drop once no deployed contract stores parameter votes by account.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldGovernanceThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, ProposedGovernanceThresholdParameters>,
}

/// Shadow of the `3.18.0` `RunningContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: GovernanceThresholdParameters,
    parameters_votes: OldGovernanceThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        // Pending parameter votes are dropped. Participants re-vote after the upgrade.
        RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters,
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// Shadow of the `3.18.0` `ResharingContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldResharingContractState {
    previous_running_state: OldRunningContractState,
    reshared_keys: Vec<KeyForDomain>,
    resharing_key: KeyEvent,
    cancellation_requests: BTreeSet<AuthenticatedAccountId>,
    per_domain_thresholds: BTreeMap<dtos::DomainId, dtos::ReconstructionThreshold>,
}

/// Shadow of the `3.18.0` `ProtocolContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(OldResharingContractState),
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.18.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    contract_update_votes: ContractUpdateVotes,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: AccountId,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        let OldProtocolContractState::Running(running_state) = old.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };
        assert_participants_own_their_tls_keys(
            running_state.parameters.participants(),
            &old.tee_state,
            &old.node_migrations,
        );

        crate::v3_19_0_state::MpcContract {
            protocol_state: ProtocolContractState::Running(running_state.into()),
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            contract_update_votes: old.contract_update_votes,
            config: old.config,
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
            parameters_votes: GovernanceThresholdParametersVotes::default(),
        }
        .into()
    }
}

fn assert_participants_own_their_tls_keys(
    participants: &Participants,
    tee_state: &TeeState,
    node_migrations: &NodeMigrations,
) {
    for (account_id, _, participant_info) in participants.participants() {
        let migration_destination = node_migrations
            .ongoing_migration(account_id)
            .map(|migration| &migration.destination_node_info.tls_public_key);
        for tls_public_key in
            iter::once(&participant_info.tls_public_key).chain(migration_destination)
        {
            if tee_state.node_of(account_id, tls_public_key).is_none() {
                env::panic_str(&format!(
                    "Participant {account_id} has no node under the TLS key {tls_public_key:?} it uses."
                ));
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::{
        api::test_utils::destination_of, primitives::test_utils::node_for,
        state::test_utils::gen_running_state, storage_keys::StorageKey,
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    fn old_contract(running_state: OldRunningContractState) -> MpcContract {
        let tee_state =
            TeeState::with_mocked_participant_attestations(running_state.parameters.participants());
        MpcContract {
            protocol_state: OldProtocolContractState::Running(running_state),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            contract_update_votes: ContractUpdateVotes::default(),
            config: Config::default(),
            tee_state,
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: "verifier.near".parse().unwrap(),
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        }
    }

    #[test]
    fn from__should_drop_pending_parameter_votes() {
        // Given: a 3.18.0 running state holding one pending parameter vote
        let running = gen_running_state(1);
        let participants = running.parameters.participants();
        let signer = participants.participants()[0].0.clone();
        testing_env!(VMContextBuilder::new().signer_account_id(signer).build());
        let voter = AuthenticatedAccountId::new(participants).unwrap();
        let proposal =
            ProposedGovernanceThresholdParameters::new(running.parameters.clone(), BTreeMap::new());
        let old = old_contract(OldRunningContractState {
            domains: running.domains.clone(),
            keyset: running.keyset.clone(),
            parameters: running.parameters.clone(),
            parameters_votes: OldGovernanceThresholdParametersVotes {
                proposal_by_account: BTreeMap::from([(voter, proposal)]),
            },
            add_domains_votes: running.add_domains_votes.clone(),
            previously_cancelled_resharing_epoch_id: running
                .previously_cancelled_resharing_epoch_id,
        });

        // When
        let migrated: crate::MpcContract = old.into();

        // Then
        assert!(migrated.parameters_votes.is_empty());
        assert_eq!(
            migrated.protocol_state,
            ProtocolContractState::Running(running)
        );
    }

    fn old_running_state() -> OldRunningContractState {
        let running = gen_running_state(1);
        OldRunningContractState {
            domains: running.domains,
            keyset: running.keyset,
            parameters: running.parameters,
            parameters_votes: OldGovernanceThresholdParametersVotes {
                proposal_by_account: BTreeMap::new(),
            },
            add_domains_votes: running.add_domains_votes,
            previously_cancelled_resharing_epoch_id: running
                .previously_cancelled_resharing_epoch_id,
        }
    }

    #[test]
    #[should_panic(expected = "has no node under the TLS key")]
    fn from__should_panic_when_a_participant_has_no_node() {
        // Given
        let running_state = old_running_state();
        let (_, _, participant_info) =
            running_state.parameters.participants().participants()[0].clone();
        let mut old = old_contract(running_state);
        old.tee_state.nodes.remove(&participant_info.tls_public_key);

        // When, Then
        let _: crate::MpcContract = old.into();
    }

    #[test]
    #[should_panic(expected = "has no node under the TLS key")]
    fn from__should_panic_when_a_migration_destination_has_no_node() {
        // Given
        let running_state = old_running_state();
        let (account_id, _, _) = running_state.parameters.participants().participants()[0].clone();
        let mut old = old_contract(running_state);
        old.node_migrations
            .set_destination_node_info(account_id.clone(), destination_of(&node_for(&account_id)));

        // When, Then
        let _: crate::MpcContract = old.into();
    }
}
