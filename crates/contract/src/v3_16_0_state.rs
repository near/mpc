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
    CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, env, require,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::key_state::AuthenticatedAccountId,
    primitives::votes::Votes,
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::measurements::{AllowedMeasurements, MeasurementVotes},
    tee::proposal::{AllowedLauncherImages, LauncherHashVotes, StoredDockerImageHashes},
    tee::tee_state::{NodeAttestation, NodeId, TeeState},
    tee::verifier_votes::TeeVerifierVotes,
    update::ContractUpdateVotes,
};
use mpc_attestation::attestation::VerifiedAttestation;
use near_mpc_contract_interface::types as dtos;

/// Shadow of the pre-[#4301](https://github.com/near/mpc/issues/4301) entry, which carries no
/// [`NodeAttestation::attested_at_seconds`].
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: NodeId,
    verified_attestation: VerifiedAttestation,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: Votes<AuthenticatedAccountId>,
    launcher_votes: LauncherHashVotes,
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
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
            stored_attestations: migrate_stored_attestations(old.stored_attestations),
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        }
    }
}

/// Adds the [`NodeAttestation::attested_at_seconds`] the old entries lack, as `None`: the
/// contract never recorded when it accepted them, and the upgrade block time would read as a
/// submission that never happened. Each node's next accepted submission stamps a real value.
///
/// This is a one-off for the layout that predates the field. A later migration must carry
/// [`NodeAttestation::attested_at_seconds`] across untouched — rewriting it would restamp every
/// node's entry.
fn migrate_stored_attestations(
    mut old: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
) -> IterableMap<dtos::Ed25519PublicKey, NodeAttestation> {
    let entries: Vec<_> = old.drain().collect();
    // Commit the removals before the new map writes under the same prefix.
    old.flush();

    let mut migrated = IterableMap::new(StorageKey::StoredAttestations);
    for (tls_public_key, entry) in entries {
        migrated.insert(
            tls_public_key,
            NodeAttestation {
                node_id: entry.node_id,
                verified_attestation: entry.verified_attestation,
                attested_at_seconds: None,
            },
        );
    }
    migrated
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
    use crate::primitives::test_utils::node_id_for;
    use crate::storage_keys::StorageKey;
    use assert_matches::assert_matches;
    use mpc_attestation::attestation::MockAttestation;
    use near_sdk::store::IterableMap;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{env, testing_env};

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

    #[test]
    fn migrate_stored_attestations__should_carry_entries_over_without_an_acceptance_time() {
        // Given: two entries written by a contract that stored no acceptance time
        testing_env!(VMContextBuilder::new().build());
        let mut old = IterableMap::new(StorageKey::StoredAttestations);
        let node_ids: Vec<_> = ["alice.near", "bob.near"]
            .iter()
            .map(|account_id| node_id_for(&account_id.parse().unwrap()))
            .collect();
        for node_id in &node_ids {
            old.insert(
                node_id.tls_public_key.clone(),
                OldNodeAttestation {
                    node_id: node_id.clone(),
                    verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
                },
            );
        }
        old.flush();

        // When
        let mut migrated = migrate_stored_attestations(old);
        migrated.flush();

        // Then: read back the way the next contract call would — through a handle rebuilt from
        // the borsh form, whose cache is empty — so the assertions come from storage and would
        // catch the new map's writes being undone by the old map's removals.
        let reread: IterableMap<dtos::Ed25519PublicKey, NodeAttestation> =
            borsh::from_slice(&borsh::to_vec(&migrated).unwrap()).unwrap();
        assert_eq!(reread.len() as usize, node_ids.len());
        for node_id in &node_ids {
            let entry = reread
                .get(&node_id.tls_public_key)
                .expect("every entry survives the migration");
            assert_eq!(entry.node_id, *node_id);
            assert_matches!(
                entry.verified_attestation,
                VerifiedAttestation::Mock(MockAttestation::Valid)
            );
            assert_eq!(entry.attested_at_seconds, None);
        }
    }
}
