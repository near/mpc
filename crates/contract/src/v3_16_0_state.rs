//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{
    CKDRequest, Ed25519PublicKey, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, env, require,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{key_state::AuthenticatedAccountId, votes::Votes},
    state::ProtocolContractState,
    tee::{
        measurements::{AllowedMeasurements, MeasurementVotes},
        proposal::{AllowedLauncherImages, LauncherHashVotes, StoredDockerImageHashes},
        tee_state::{AttestationStore, NodeAttestation, TeeState},
        verifier_votes::TeeVerifierVotes,
    },
    update::ContractUpdateVotes,
};

/// The `3.16.0` [`TeeState`], whose attestations had no index by account public key.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: Votes<AuthenticatedAccountId>,
    launcher_votes: LauncherHashVotes,
    stored_attestations: IterableMap<Ed25519PublicKey, NodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: MeasurementVotes,
}

impl From<OldTeeState> for TeeState {
    fn from(old: OldTeeState) -> Self {
        TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: old.votes,
            launcher_votes: old.launcher_votes,
            // Indexing the entries here would walk a map anyone can grow, inside the upgrade
            // receipt's fixed gas budget.
            stored_attestations: AttestationStore::from_unindexed_map(old.stored_attestations),
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        }
    }
}

/// A stored proposal holds a whole contract binary, so the migration clears both maps.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ProposedUpdates {
    vote_by_participant: IterableMap<AccountId, UpdateId>,
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

impl ProposedUpdates {
    fn clear_storage(mut self) {
        self.vote_by_participant.clear();
        self.entries.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
struct UpdateId(u64);

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct UpdateEntry {
    update: Update,
    bytes_used: u128,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum Update {
    Contract(Vec<u8>),
    Config(Config),
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.16.0` contract still deserializes during migration.
///
/// This module reads the *current* [`ProtocolContractState`], so a bound added to a stored type
/// is also an upgrade gate: state the new type rejects cannot be migrated.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
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
        require!(
            matches!(old.protocol_state, ProtocolContractState::Running(_)),
            "Contract must be in running state when migrating."
        );
        old.proposed_updates.clear_storage();

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
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
            contract_update_votes: ContractUpdateVotes::default(),
        }
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
    use crate::tee::tee_state::NodeId;
    use mpc_attestation::attestation::{MockAttestation, VerifiedAttestation};
    use near_mpc_contract_interface::types as dtos;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::collections::BTreeSet;

    #[test]
    fn proposed_updates__clear_storage__should_release_the_stored_proposals_and_votes() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let baseline = env::storage_usage();
        let mut proposals = ProposedUpdates {
            vote_by_participant: IterableMap::new(StorageKey::_DeprecatedProposedUpdatesVotesV2),
            entries: IterableMap::new(StorageKey::_DeprecatedProposedUpdatesEntriesV2),
            id: UpdateId(1),
        };
        proposals.entries.insert(
            UpdateId(0),
            UpdateEntry {
                update: Update::Contract(vec![7; 4096]),
                bytes_used: 4096,
            },
        );
        proposals
            .vote_by_participant
            .insert("alice.near".parse().unwrap(), UpdateId(0));
        proposals.entries.flush();
        proposals.vote_by_participant.flush();
        assert!(env::storage_usage() > baseline);

        // When
        proposals.clear_storage();

        // Then
        assert_eq!(env::storage_usage(), baseline);
    }

    struct AttestedNode {
        account_id: AccountId,
        tls_public_key: Ed25519PublicKey,
        account_public_key: Ed25519PublicKey,
    }

    impl AttestedNode {
        fn new(account_id: AccountId) -> Self {
            Self {
                account_id,
                tls_public_key: bogus_ed25519_public_key(),
                account_public_key: bogus_ed25519_public_key(),
            }
        }

        fn node_attestation(&self) -> NodeAttestation {
            NodeAttestation {
                node_id: NodeId {
                    account_id: self.account_id.clone(),
                    tls_public_key: self.tls_public_key.clone(),
                    account_public_key: self.account_public_key.clone(),
                },
                verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
            }
        }

        fn sign_as(&self) {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(self.account_id.clone())
                    .predecessor_account_id(self.account_id.clone())
                    .signer_account_pk(near_sdk::PublicKey::from(self.account_public_key.clone()))
                    .build()
            );
        }
    }

    /// A `3.16.0` contract in Running state holding the attestation of a participant and of a
    /// non participant, in that order.
    fn contract_3_16_0_with_stored_attestations() -> (MpcContract, [AttestedNode; 2]) {
        testing_env!(VMContextBuilder::new().build());
        let participants = gen_participants(2);
        let (participant_account_id, _, _) = participants.participants()[0].clone();
        let parameters =
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
        let nodes = [
            AttestedNode::new(participant_account_id),
            AttestedNode::new("other.near".parse().unwrap()),
        ];

        let mut stored_attestations =
            IterableMap::<Ed25519PublicKey, NodeAttestation>::new(StorageKey::StoredAttestations);
        for node in &nodes {
            stored_attestations.insert(node.tls_public_key.clone(), node.node_attestation());
        }

        let contract = MpcContract {
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
            proposed_updates: ProposedUpdates {
                vote_by_participant: IterableMap::new(
                    StorageKey::_DeprecatedProposedUpdatesVotesV2,
                ),
                entries: IterableMap::new(StorageKey::_DeprecatedProposedUpdatesEntriesV2),
                id: UpdateId(0),
            },
            config: Config::default(),
            tee_state: OldTeeState {
                allowed_docker_image_hashes: StoredDockerImageHashes::default(),
                allowed_launcher_images: AllowedLauncherImages::default(),
                votes: Votes::new(
                    StorageKey::CodeHashVotesByVoter,
                    StorageKey::CodeHashVotesByProposal,
                ),
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
            tee_verifier_account_id: Some("tee-verifier.near".parse().unwrap()),
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        };
        (contract, nodes)
    }

    #[test]
    fn migration__should_keep_register_foreign_chains_config_working_through_the_fallback_scan() {
        // Given
        let (old, nodes) = contract_3_16_0_with_stored_attestations();
        let participant = &nodes[0];

        // When
        let mut contract: crate::MpcContract = old.into();
        participant.sign_as();
        let result = contract
            .register_foreign_chains_config(BTreeSet::from([dtos::ForeignChain::Bitcoin]).into());

        // Then
        assert_eq!(result, Ok(()));
        assert!(
            contract
                .foreign_chains
                .get()
                .foreign_chains_configs
                .contains_key(&participant.tls_public_key)
        );
        for node in &nodes {
            assert!(
                !contract
                    .tee_state
                    .stored_attestations
                    .is_indexed(&node.account_public_key)
            );
        }
    }

    #[test]
    fn migration__should_index_an_adopted_attestation_once_its_node_re_attests() {
        // Given
        let (old, nodes) = contract_3_16_0_with_stored_attestations();
        let participant = &nodes[0];
        let mut contract: crate::MpcContract = old.into();
        participant.sign_as();

        // When
        let result = contract.submit_participant_info(
            dtos::Attestation::Mock(dtos::MockAttestation::Valid),
            participant.tls_public_key.clone(),
        );

        // Then
        // assert_matches! requires Debug, and PromiseOrValue has none
        assert!(matches!(result, Ok(near_sdk::PromiseOrValue::Value(()))));
        let stored_attestations = &contract.tee_state.stored_attestations;
        assert!(stored_attestations.is_indexed(&participant.account_public_key));
        assert_eq!(
            stored_attestations
                .get_by_account_key(&participant.account_public_key)
                .map(|attestation| &attestation.node_id.tls_public_key),
            Some(&participant.tls_public_key)
        );
    }
}
