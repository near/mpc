//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::VerifiedAttestation;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{env, store::LookupMap};
use std::collections::BTreeMap;

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::{
        measurements::{AllowedMeasurements, MeasurementVotes},
        proposal::{
            AllowedDockerImageHashes, AllowedLauncherImages, CodeHashesVotes, LauncherHashVotes,
        },
        tee_state::{NodeAttestation, TeeState},
    },
    update::ProposedUpdates,
    Config, ForeignChainPolicyVotes, NodeForeignChainConfigurations,
};

/// Previous `StaleData` layout — held a [`LookupMap`] of pre-upgrade signature requests.
/// After the v3.9 migration is fully deployed those requests have been resolved or timed
/// out, so the field is dropped here and the new `StaleData` is empty.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldStaleData {
    pending_signature_requests_pre_upgrade: LookupMap<SignatureRequest, YieldIndex>,
}

/// Previous `NodeId` layout — `tls_public_key` and `account_public_key` used the
/// `near_sdk::PublicKey` tagged borsh encoding. The new layout stores the TLS
/// key as a raw 32-byte [`dtos::Ed25519PublicKey`] and the account key as a
/// [`dtos::PublicKey`] (with an explicit curve tag), so we need a dedicated
/// pre-migration type here.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeId {
    account_id: AccountId,
    tls_public_key: near_sdk::PublicKey,
    account_public_key: Option<near_sdk::PublicKey>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: OldNodeId,
    verified_attestation: VerifiedAttestation,
}

/// Previous `TeeState` layout — the `stored_attestations` map was keyed by
/// `near_sdk::PublicKey` (TLS key with curve tag) and held [`OldNodeAttestation`].
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: AllowedDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: CodeHashesVotes,
    launcher_votes: LauncherHashVotes,
    stored_attestations: BTreeMap<near_sdk::PublicKey, OldNodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: MeasurementVotes,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: dtos::ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    node_foreign_chain_configurations: NodeForeignChainConfigurations,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: OldStaleData,
    metrics: dtos::Metrics,
}

impl From<OldTeeState> for TeeState {
    fn from(old: OldTeeState) -> Self {
        // Migrate entry-by-entry: skip any whose TLS key is not Ed25519, and
        // drop non-Ed25519 `account_public_key` values. A stored non-Ed25519
        // TLS key could never match the node's actual key (the contract
        // always signed with Ed25519), so dropping it is safe — we prefer
        // silent skip over panic to avoid bricking the migration transaction
        // on pathological stored state.
        let stored_attestations = old
            .stored_attestations
            .into_iter()
            .filter_map(|(tls_pk, old_attestation)| {
                let new_tls_key = dtos::Ed25519PublicKey::try_from(&tls_pk).ok()?;
                let account_public_key = old_attestation
                    .node_id
                    .account_public_key
                    .as_ref()
                    .and_then(|pk| dtos::Ed25519PublicKey::try_from(pk).ok());
                let node_id = dtos::NodeId {
                    account_id: old_attestation.node_id.account_id,
                    tls_public_key: new_tls_key.clone(),
                    account_public_key,
                };
                Some((
                    new_tls_key,
                    NodeAttestation {
                        node_id,
                        verified_attestation: old_attestation.verified_attestation,
                    },
                ))
            })
            .collect();

        TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: old.votes,
            launcher_votes: old.launcher_votes,
            stored_attestations,
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        }
    }
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        if !matches!(value.protocol_state, ProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy: value.foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            node_foreign_chain_configurations: value.node_foreign_chain_configurations,
            config: value.config,
            tee_state: value.tee_state.into(),
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {},
            metrics: value.metrics,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_attestation::attestation::MockAttestation;

    fn old_ed25519_near_pk(byte: u8) -> near_sdk::PublicKey {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, vec![byte; 32]).unwrap()
    }

    fn old_secp256k1_near_pk(byte: u8) -> near_sdk::PublicKey {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, vec![byte; 64]).unwrap()
    }

    fn old_attestation(
        account_id: &str,
        tls_pk: near_sdk::PublicKey,
        account_pk: Option<near_sdk::PublicKey>,
    ) -> OldNodeAttestation {
        OldNodeAttestation {
            node_id: OldNodeId {
                account_id: account_id.parse().unwrap(),
                tls_public_key: tls_pk,
                account_public_key: account_pk,
            },
            verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
        }
    }

    #[test]
    fn tee_state_migration__should_rekey_stored_attestations_to_ed25519() {
        // Given
        let tls_pk = old_ed25519_near_pk(7);
        let account_pk = old_ed25519_near_pk(8);
        let mut old = OldTeeState::default();
        old.stored_attestations.insert(
            tls_pk.clone(),
            old_attestation("carol.near", tls_pk, Some(account_pk)),
        );

        // When
        let new: TeeState = old.into();

        // Then
        assert_eq!(new.stored_attestations.len(), 1);
        let expected_key = dtos::Ed25519PublicKey::from([7u8; 32]);
        let stored = new
            .stored_attestations
            .get(&expected_key)
            .expect("entry rekeyed to Ed25519PublicKey");
        assert_eq!(stored.node_id.tls_public_key, expected_key);
        assert_eq!(
            stored.node_id.account_public_key,
            Some(dtos::Ed25519PublicKey::from([8u8; 32]))
        );
    }

    #[test]
    fn tee_state_migration__should_preserve_missing_account_key() {
        // Given a legacy/mock node that never recorded an account key
        let tls_pk = old_ed25519_near_pk(1);
        let mut old = OldTeeState::default();
        old.stored_attestations
            .insert(tls_pk.clone(), old_attestation("bob.near", tls_pk, None));

        // When
        let new: TeeState = old.into();

        // Then
        let expected_key = dtos::Ed25519PublicKey::from([1u8; 32]);
        let stored = new.stored_attestations.get(&expected_key).unwrap();
        assert_eq!(stored.node_id.account_public_key, None);
    }

    #[test]
    fn tee_state_migration__should_skip_entries_with_non_ed25519_tls_key() {
        // Given one Ed25519 entry and one secp256k1 entry in the old state
        let good_tls = old_ed25519_near_pk(4);
        let bad_tls = old_secp256k1_near_pk(5);
        let mut old = OldTeeState::default();
        old.stored_attestations.insert(
            good_tls.clone(),
            old_attestation("good.near", good_tls, None),
        );
        old.stored_attestations
            .insert(bad_tls.clone(), old_attestation("bad.near", bad_tls, None));

        // When
        let new: TeeState = old.into();

        // Then the secp256k1 entry is dropped, the Ed25519 entry survives
        assert_eq!(new.stored_attestations.len(), 1);
        assert!(new
            .stored_attestations
            .contains_key(&dtos::Ed25519PublicKey::from([4u8; 32])));
    }

    #[test]
    fn tee_state_migration__should_drop_non_ed25519_account_key() {
        // Given a stored entry whose account_public_key is (unexpectedly) secp256k1
        let tls_pk = old_ed25519_near_pk(2);
        let secp_account_pk = old_secp256k1_near_pk(3);
        let mut old = OldTeeState::default();
        old.stored_attestations.insert(
            tls_pk.clone(),
            old_attestation("x.near", tls_pk, Some(secp_account_pk)),
        );

        // When
        let new: TeeState = old.into();

        // Then the entry is kept but its account key is cleared
        let stored = new
            .stored_attestations
            .get(&dtos::Ed25519PublicKey::from([2u8; 32]))
            .unwrap();
        assert_eq!(stored.node_id.account_public_key, None);
    }

    #[test]
    fn tee_state_migration__should_round_trip_through_borsh() {
        // Given an OldTeeState serialized with borsh (mirrors the on-chain path)
        let tls_pk = old_ed25519_near_pk(9);
        let mut pre_migration = OldTeeState::default();
        pre_migration
            .stored_attestations
            .insert(tls_pk.clone(), old_attestation("dave.near", tls_pk, None));
        let bytes = borsh::to_vec(&pre_migration).unwrap();

        // When
        let decoded: OldTeeState = borsh::from_slice(&bytes).unwrap();
        let migrated: TeeState = decoded.into();

        // Then
        let expected_key = dtos::Ed25519PublicKey::from([9u8; 32]);
        assert!(migrated.stored_attestations.contains_key(&expected_key));
    }
}
