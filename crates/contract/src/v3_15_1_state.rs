//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::{
    CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, env,
    store::{IterableMap, Lazy, LookupMap},
};
use std::collections::BTreeSet;

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{key_state::AuthenticatedParticipantId, votes::Votes},
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::{
        measurements::{AllowedMeasurements, MeasurementVotes},
        proposal::{
            AllowedLauncherImages, LauncherHashVotes, NodeImageHash, StoredDockerImageHashes,
        },
        tee_state::{AttestationStore, NodeAttestation, TeeState},
        verifier_votes::TeeVerifierVotes,
    },
    update::ProposedUpdates,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldCodeHashesVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, NodeImageHash>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: OldCodeHashesVotes,
    launcher_votes: LauncherHashVotes,
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, NodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: MeasurementVotes,
}

impl From<OldTeeState> for TeeState {
    fn from(old: OldTeeState) -> Self {
        // Pending code-hash votes are dropped. We don't need to optimize for this and it's not
        // worth the review & testing effort.
        TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: Votes::new(
                StorageKey::CodeHashVotesByVoter,
                StorageKey::CodeHashVotesByProposal,
            ),
            launcher_votes: old.launcher_votes,
            stored_attestations: AttestationStore::from_value_map(old.stored_attestations),
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        }
    }
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.15.1` contract still deserializes during migration.
///
/// This module reads the *current* [`ProtocolContractState`], so a bound added to a stored type
/// is also an upgrade gate: state the new type rejects cannot be migrated. That is deliberate for
/// [`ParticipantUrl`](crate::primitives::participants::ParticipantUrl) — a url over the bound
/// fails [`crate::MpcContract::migrate`] and rolls the deploy back, rather than being silently
/// truncated. Check the participant set before deploying a change of that kind.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: OldSupportedForeignChainsByNode,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: Option<AccountId>,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        if !matches!(old.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }
        old.node_foreign_chain_support.clear_storage();

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            config: old.config,
            tee_state: old.tee_state.into(),
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id.unwrap_or_else(|| {
                env::panic_str(
                    "No TEE verifier is configured. Participants must vote one in via vote_tee_verifier_change before upgrading.",
                )
            }),
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
        }
    }
}

/// Shadow of the `3.15.1` legacy account-keyed support map; the migration clears it.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldSupportedForeignChainsByNode {
    foreign_chain_support_by_node: IterableMap<dtos::AccountId, BTreeSet<dtos::ForeignChain>>,
}

impl OldSupportedForeignChainsByNode {
    fn clear_storage(mut self) {
        self.foreign_chain_support_by_node.clear();
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::domain::{AddDomainsVotes, DomainRegistry};
    use crate::primitives::key_state::{EpochId, Keyset};
    use crate::primitives::test_utils::{bogus_ed25519_public_key, gen_participants};
    use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
    use crate::state::running::RunningContractState;
    use crate::storage_keys::StorageKey;
    use mpc_attestation::attestation::{MockAttestation, VerifiedAttestation};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::collections::BTreeMap;

    #[test]
    fn old_supported_foreign_chains_by_node__clear_storage__should_release_all_entries() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let baseline = env::storage_usage();
        let mut legacy = OldSupportedForeignChainsByNode {
            foreign_chain_support_by_node: IterableMap::new(
                StorageKey::_DeprecatedSupportedForeignChainsByNode,
            ),
        };
        legacy.foreign_chain_support_by_node.insert(
            "alice.near".parse().unwrap(),
            BTreeSet::from([dtos::ForeignChain::Bitcoin]),
        );
        legacy.foreign_chain_support_by_node.insert(
            "bob.near".parse().unwrap(),
            BTreeSet::from([dtos::ForeignChain::Solana]),
        );
        legacy.foreign_chain_support_by_node.flush();
        assert!(env::storage_usage() > baseline);

        // When
        legacy.clear_storage();

        // Then
        assert_eq!(env::storage_usage(), baseline);
    }

    /// Simulates the upgrade from a `3.15.1` deployment: state whose attestations are
    /// keyed by TLS public key only. The migration must rebuild the reverse index from
    /// the stored entries so caller resolution by account public key works right after.
    #[test]
    fn migration__should_rebuild_the_attestation_index_and_keep_register_working() {
        // Given: a `3.15.1` layout contract in Running state, with two stored
        // attestations, one of them for `operator.near` under account key K.
        testing_env!(VMContextBuilder::new().build());

        let participants = gen_participants(2);
        let (operator, _, _) = participants.participants().iter().next().unwrap().clone();
        let parameters =
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
        let other: near_sdk::AccountId = "other.near".parse().unwrap();

        let operator_tls_pk = bogus_ed25519_public_key();
        let operator_account_pk = bogus_ed25519_public_key();
        let other_tls_pk = bogus_ed25519_public_key();
        let other_account_pk = bogus_ed25519_public_key();

        let mut stored_attestations = IterableMap::<dtos::Ed25519PublicKey, NodeAttestation>::new(
            StorageKey::StoredAttestations,
        );
        for (tls_pk, account_pk, account_id) in [
            (&operator_tls_pk, &operator_account_pk, &operator),
            (&other_tls_pk, &other_account_pk, &other),
        ] {
            stored_attestations.insert(
                tls_pk.clone(),
                NodeAttestation {
                    node_id: crate::tee::tee_state::NodeId {
                        account_id: account_id.clone(),
                        tls_public_key: tls_pk.clone(),
                        account_public_key: account_pk.clone(),
                    },
                    verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
                },
            );
        }

        let old = MpcContract {
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                DomainRegistry::default(),
                Keyset::new(EpochId::new(0), Vec::new()),
                parameters,
                AddDomainsVotes::default(),
            )),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            proposed_updates: ProposedUpdates::default(),
            node_foreign_chain_support: OldSupportedForeignChainsByNode {
                foreign_chain_support_by_node: IterableMap::new(
                    StorageKey::_DeprecatedSupportedForeignChainsByNode,
                ),
            },
            config: Config::default(),
            tee_state: OldTeeState {
                allowed_docker_image_hashes: StoredDockerImageHashes::default(),
                allowed_launcher_images: AllowedLauncherImages::default(),
                votes: OldCodeHashesVotes {
                    proposal_by_account: BTreeMap::new(),
                },
                launcher_votes: LauncherHashVotes::default(),
                stored_attestations,
                allowed_measurements: AllowedMeasurements::default(),
                measurement_votes: MeasurementVotes::default(),
            },
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: None,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        };

        // When: the contract migrates, walking the old map into the new store.
        let mut contract: crate::MpcContract = old.into();

        // Then: both account keys resolve through the rebuilt index.
        let migrated_operator = contract
            .tee_state
            .stored_attestations
            .get_by_account_key(&operator_account_pk)
            .expect("operator account key must resolve after migration");
        assert_eq!(migrated_operator.node_id.account_id, operator);
        assert_eq!(migrated_operator.node_id.tls_public_key, operator_tls_pk);
        let migrated_other = contract
            .tee_state
            .stored_attestations
            .get_by_account_key(&other_account_pk)
            .expect("other account key must resolve after migration");
        assert_eq!(migrated_other.node_id.tls_public_key, other_tls_pk);

        // And: a caller signing with its recorded account key can register foreign
        // chains right after the upgrade.
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(operator.clone())
                .predecessor_account_id(operator.clone())
                .signer_account_pk(near_sdk::PublicKey::from(operator_account_pk))
                .build()
        );
        let foreign_chains_config: dtos::ForeignChainsConfig =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("register must work right after the migration");
        assert!(
            contract
                .foreign_chains
                .get()
                .foreign_chains_configs
                .contains_key(&operator_tls_pk)
        );
    }
}
