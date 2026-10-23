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
use near_mpc_contract_interface::types::{
    self as dtos, CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId, require,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{
        key_state::{AuthenticatedAccountId, AuthenticatedParticipantId},
        votes::Votes,
    },
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::{
        measurements::AllowedMeasurements,
        proposal::{AllowedLauncherImages, StoredDockerImageHashes},
        tee_state::{Node, NodeId, TeeState},
        verifier_votes::TeeVerifierVotes,
    },
    update::ContractUpdateVotes,
};

/// Shadow of the `3.17.0` `LauncherHashVotes` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldLauncherHashVotes {
    vote_by_account: BTreeMap<AuthenticatedParticipantId, dtos::LauncherVoteAction>,
}

/// Shadow of the `3.17.0` `MeasurementVotes` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldMeasurementVotes {
    vote_by_account: BTreeMap<AuthenticatedParticipantId, dtos::MeasurementVoteAction>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: Votes<AuthenticatedAccountId>,
    launcher_votes: OldLauncherHashVotes,
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: OldMeasurementVotes,
}

impl OldTeeState {
    fn migrate(self) -> TeeState {
        let nodes = migrate_stored_attestations(self.stored_attestations);
        // Pending votes are dropped rather than migrated; participants re-vote after the
        // upgrade.
        TeeState {
            allowed_docker_image_hashes: self.allowed_docker_image_hashes,
            allowed_launcher_images: self.allowed_launcher_images,
            votes: self.votes,
            launcher_votes: Votes::new(
                StorageKey::LauncherHashVotesByVoter,
                StorageKey::LauncherHashVotesByProposal,
            ),
            nodes,
            allowed_measurements: self.allowed_measurements,
            measurement_votes: Votes::new(
                StorageKey::MeasurementVotesByVoter,
                StorageKey::MeasurementVotesByProposal,
            ),
        }
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: NodeId,
    verified_attestation: VerifiedAttestation,
    accepted_at_seconds: Option<u64>,
}

fn migrate_stored_attestations(
    mut old: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
) -> IterableMap<dtos::Ed25519PublicKey, Node> {
    let entries: Vec<_> = old.drain().collect();
    // The rebuilt map shares the storage prefix, so its inserts would read the drained entries
    // back from storage until the removals are written
    old.flush();

    let mut migrated = IterableMap::new(StorageKey::StoredAttestations);
    for (tls_public_key, entry) in entries {
        if let Some(accepted_at_seconds) = entry.accepted_at_seconds {
            migrated.insert(
                tls_public_key,
                Node {
                    account_id: entry.node_id.account_id,
                    tls_public_key: entry.node_id.tls_public_key,
                    account_public_key: entry.node_id.account_public_key,
                    attestation: entry.verified_attestation,
                    accepted_at_seconds,
                },
            );
        }
    }
    migrated
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.17.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    contract_update_votes: ContractUpdateVotes,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: AccountId,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        require!(
            matches!(old.protocol_state, ProtocolContractState::Running(_)),
            "Contract must be in running state when migrating."
        );

        let tee_state = old.tee_state.migrate();
        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            contract_update_votes: old.contract_update_votes,
            config: old.config,
            tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::node_id_for;
    use mpc_attestation::attestation::MockAttestation;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    #[test]
    fn migrate_stored_attestations__should_evict_entries_without_an_acceptance_time() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let accepted_at = 1_800_000_000;
        let stamped = node_id_for(&"alice.near".parse().unwrap());
        let unstamped = node_id_for(&"bob.near".parse().unwrap());
        let mut old = IterableMap::new(StorageKey::StoredAttestations);
        for (node_id, accepted_at_seconds) in [(&stamped, Some(accepted_at)), (&unstamped, None)] {
            old.insert(
                node_id.tls_public_key.clone(),
                OldNodeAttestation {
                    node_id: node_id.clone(),
                    verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
                    accepted_at_seconds,
                },
            );
        }
        old.flush();

        // When
        let migrated = migrate_stored_attestations(old);

        // Then
        let migrated: Vec<_> = migrated
            .values()
            .map(|node| (node.id(), node.accepted_at_seconds))
            .collect();
        assert_eq!(migrated, vec![(stamped, accepted_at)]);
    }
}
