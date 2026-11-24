//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::hash::GenesisHash;
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
        key_state::{
            AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain, Keyset,
        },
        threshold_votes::GovernanceThresholdParametersVotes,
        thresholds::GovernanceThresholdParameters,
    },
    state::{
        ProtocolContractState, initializing::InitializingContractState, key_event::KeyEvent,
        running::RunningContractState,
    },
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ContractUpdateVotes,
};

/// Shadow of the `3.19.0` `AddDomainsVotes` layout.
// TODO(#5277): drop once no deployed contract stores add-domains votes by account.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldAddDomainsVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<dtos::DomainConfig>>,
}

/// Shadow of the `3.19.0` `RunningContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: GovernanceThresholdParameters,
    add_domains_votes: OldAddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        // Pending add-domains votes are dropped. Participants re-vote after the upgrade.
        RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// Shadow of the `3.19.0` `ResharingContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldResharingContractState {
    previous_running_state: OldRunningContractState,
    reshared_keys: Vec<KeyForDomain>,
    resharing_key: KeyEvent,
    cancellation_requests: BTreeSet<AuthenticatedAccountId>,
    per_domain_thresholds: BTreeMap<dtos::DomainId, dtos::ReconstructionThreshold>,
}

/// Shadow of the `3.19.0` `ProtocolContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(OldResharingContractState),
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.19.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    contract_update_votes: ContractUpdateVotes,
    config: OldConfig,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: AccountId,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
    parameters_votes: GovernanceThresholdParametersVotes,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        let OldProtocolContractState::Running(running_state) = old.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        crate::MpcContract {
            protocol_state: ProtocolContractState::Running(running_state.into()),
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            contract_update_votes: old.contract_update_votes,
            config: old.config.into(),
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
            parameters_votes: old.parameters_votes,
            genesis_hash: genesis_hash_of(&env::chain_id()),
            add_domains_votes: AddDomainsVotes::default(),
        }
    }
}

/// Shadow of the `3.19.0` [`Config`] layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(Default))]
struct OldConfig {
    key_event_timeout_blocks: dtos::BlockCount,
    tee_upgrade_deadline_duration_seconds: u64,
    apply_contract_update_tera_gas: u64,
    sign_call_gas_attachment_requirement_tera_gas: u64,
    ckd_call_gas_attachment_requirement_tera_gas: u64,
    return_signature_and_clean_state_on_success_call_tera_gas: u64,
    return_ck_and_clean_state_on_success_call_tera_gas: u64,
    fail_on_timeout_tera_gas: u64,
    fail_attestation_submission_tera_gas: u64,
    clean_tee_status_tera_gas: u64,
    clean_invalid_attestations_tera_gas: u64,
    cleanup_orphaned_node_migrations_tera_gas: u64,
    remove_non_participant_update_votes_tera_gas: u64,
    clean_foreign_chain_data_tera_gas: u64,
    remove_non_participant_tee_verifier_votes_tera_gas: u64,
    verifier_tera_gas: u64,
    resolve_verification_tera_gas: u64,
    launcher_hash_unused_ttl_seconds: u64,
    attestation_storage_fee_millinear: u64,
}

impl From<OldConfig> for Config {
    fn from(old: OldConfig) -> Self {
        Config {
            key_event_timeout_blocks: old.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: old.tee_upgrade_deadline_duration_seconds,
            apply_contract_update_tera_gas: old.apply_contract_update_tera_gas,
            sign_call_gas_attachment_requirement_tera_gas: old
                .sign_call_gas_attachment_requirement_tera_gas,
            ckd_call_gas_attachment_requirement_tera_gas: old
                .ckd_call_gas_attachment_requirement_tera_gas,
            return_signature_and_clean_state_on_success_call_tera_gas: old
                .return_signature_and_clean_state_on_success_call_tera_gas,
            return_ck_and_clean_state_on_success_call_tera_gas: old
                .return_ck_and_clean_state_on_success_call_tera_gas,
            fail_on_timeout_tera_gas: old.fail_on_timeout_tera_gas,
            fail_attestation_submission_tera_gas: old.fail_attestation_submission_tera_gas,
            clean_tee_status_tera_gas: old.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: old.clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: old
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: old
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: old.clean_foreign_chain_data_tera_gas,
            remove_non_participant_tee_verifier_votes_tera_gas: old
                .remove_non_participant_tee_verifier_votes_tera_gas,
            verifier_tera_gas: old.verifier_tera_gas,
            resolve_verification_tera_gas: old.resolve_verification_tera_gas,
            launcher_hash_unused_ttl_seconds: old.launcher_hash_unused_ttl_seconds,
            attestation_storage_fee_millinear: old.attestation_storage_fee_millinear,
            migration_genesis_hash: None,
        }
    }
}

/// The `3.19.0` contract does not store the genesis hash of its chain. Its chain id tells the
/// genesis hash only for mainnet and testnet, so a contract on any other chain gets none.
fn genesis_hash_of(chain_id: &str) -> Option<GenesisHash> {
    match chain_id {
        "mainnet" => Some(GenesisHash::MAINNET),
        "testnet" => Some(GenesisHash::TESTNET),
        _ => None,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::state::test_utils::gen_running_state;
    use crate::storage_keys::StorageKey;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use rstest::rstest;
    use test_utils::contract_types::dummy_config;

    fn old_contract(protocol_state: OldProtocolContractState) -> MpcContract {
        MpcContract {
            protocol_state,
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            contract_update_votes: ContractUpdateVotes::default(),
            config: OldConfig::default(),
            tee_state: TeeState::default(),
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: "verifier.near".parse().unwrap(),
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: GovernanceThresholdParametersVotes::default(),
        }
    }

    #[test]
    fn from__should_drop_pending_add_domains_votes() {
        // Given: a 3.19.0 running state holding one pending add-domains vote
        let running = gen_running_state(1);
        let participants = running.parameters.participants();
        let signer = participants.participants()[0].0.clone();
        testing_env!(VMContextBuilder::new().signer_account_id(signer).build());
        let voter = AuthenticatedParticipantId::new(participants).unwrap();
        let old = old_contract(OldProtocolContractState::Running(OldRunningContractState {
            domains: running.domains.clone(),
            keyset: running.keyset.clone(),
            parameters: running.parameters.clone(),
            add_domains_votes: OldAddDomainsVotes {
                proposal_by_account: BTreeMap::from([(voter, Vec::new())]),
            },
            previously_cancelled_resharing_epoch_id: running
                .previously_cancelled_resharing_epoch_id,
        }));

        // When
        let migrated: crate::MpcContract = old.into();

        // Then
        assert!(migrated.add_domains_votes.is_empty());
        assert_eq!(
            migrated.protocol_state,
            ProtocolContractState::Running(running)
        );
    }

    #[test]
    fn config_from__should_keep_every_3_19_0_value() {
        // Given
        let config = Config {
            migration_genesis_hash: None,
            ..Config::from(dummy_config(1))
        };
        let bytes = borsh::to_vec(&config).unwrap();
        let (_migration_genesis_hash, old_layout) = bytes.split_last().unwrap();
        let old_config = OldConfig::try_from_slice(old_layout).unwrap();

        // When
        let migrated = Config::from(old_config);

        // Then
        assert_eq!(migrated, config);
    }

    #[rstest]
    #[case::mainnet("mainnet", Some(GenesisHash::MAINNET))]
    #[case::testnet("testnet", Some(GenesisHash::TESTNET))]
    #[case::other_chain("localnet", None)]
    fn genesis_hash_of__should_return_the_genesis_hash_of_mainnet_and_testnet_only(
        #[case] chain_id: &str,
        #[case] expected: Option<GenesisHash>,
    ) {
        // When
        let genesis_hash = genesis_hash_of(chain_id);

        // Then
        assert_eq!(genesis_hash, expected);
    }
}
