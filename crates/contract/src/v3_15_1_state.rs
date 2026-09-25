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
use mpc_attestation::attestation::VerifiedAttestation;
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
        tee_state::{NodeAttestation, NodeId, TeeState},
        verifier_votes::TeeVerifierVotes,
    },
    update::ProposedUpdates,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldCodeHashesVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, NodeImageHash>,
}

/// Shadow of the pre-[#4301](https://github.com/near/mpc/issues/4301) entry, which carries no
/// `attested_at_seconds`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: NodeId,
    verified_attestation: VerifiedAttestation,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: OldCodeHashesVotes,
    launcher_votes: LauncherHashVotes,
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: MeasurementVotes,
}

/// Adds the `attested_at_seconds` the old entries lack, as `None`: the contract never recorded
/// when it accepted them, and the upgrade block time would read as a submission that never
/// happened. Each node's next accepted submission stamps a real value.
///
/// This is a one-off for the layout that predates the field. A later migration must carry
/// `attested_at_seconds` across untouched — rewriting it would restamp every node's entry.
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
            stored_attestations: migrate_stored_attestations(old.stored_attestations),
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
    use crate::primitives::test_utils::node_id_for;
    use crate::storage_keys::StorageKey;
    use assert_matches::assert_matches;
    use mpc_attestation::attestation::MockAttestation;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

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
