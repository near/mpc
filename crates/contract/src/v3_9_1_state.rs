//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use dtos::{DomainConfig, Ed25519PublicKey, ParticipantId, Threshold};
use mpc_attestation::attestation::VerifiedAttestation;
use near_account_id::AccountId;
use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{
    env,
    store::{IterableMap, LookupMap},
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        participants::{ParticipantInfo, Participants},
        signature::{SignatureRequest, YieldIndex},
        threshold_votes::ThresholdParametersVotes,
        thresholds::ThresholdParameters,
    },
    state::{
        initializing::InitializingContractState,
        key_event::{KeyEvent, KeyEventInstance},
        resharing::ResharingContractState,
        running::RunningContractState,
        ProtocolContractState,
    },
    storage_keys::StorageKey,
    tee::{
        measurements::{AllowedMeasurements, MeasurementVotes},
        proposal::{
            AllowedDockerImageHashes, AllowedLauncherImages, CodeHashesVotes, LauncherHashVotes,
        },
        tee_state::{NodeAttestation, TeeState},
    },
    update::ProposedUpdates,
    Config, SupportedForeignChainsByNode,
};

/// Previous `ParticipantInfo` layout — the TLS key was stored as a tagged
/// `near_sdk::PublicKey` under the misleading `sign_pk` name. The new layout
/// is a raw [`Ed25519PublicKey`] field named `tls_public_key`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldParticipantInfo {
    url: String,
    sign_pk: near_sdk::PublicKey,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct NodeForeignChainConfigurations {
    foreign_chain_configuration_by_node:
        IterableMap<dtos::AccountId, dtos::ForeignChainConfiguration>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldParticipants {
    next_id: ParticipantId,
    participants: Vec<(AccountId, ParticipantId, OldParticipantInfo)>,
}

/// Preserve the current `ThresholdParameters` field order so the borsh layout
/// matches the old on-chain state.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldThresholdParameters {
    participants: OldParticipants,
    threshold: Threshold,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, OldThresholdParameters>,
}

/// Mirror of the current `KeyEvent` with `OldThresholdParameters` swapped in.
/// `KeyEventInstance` does not transitively contain `ParticipantInfo`, so it
/// is reused as-is.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldKeyEvent {
    epoch_id: EpochId,
    domain: DomainConfig,
    parameters: OldThresholdParameters,
    instance: Option<KeyEventInstance>,
    next_attempt_id: AttemptId,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: OldThresholdParameters,
    parameters_votes: OldThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldInitializingContractState {
    domains: DomainRegistry,
    epoch_id: EpochId,
    generated_keys: Vec<KeyForDomain>,
    generating_key: OldKeyEvent,
    cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldResharingContractState {
    previous_running_state: OldRunningContractState,
    reshared_keys: Vec<KeyForDomain>,
    resharing_key: OldKeyEvent,
    cancellation_requests: HashSet<AuthenticatedAccountId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(OldInitializingContractState),
    Running(OldRunningContractState),
    Resharing(OldResharingContractState),
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct ForeignChainPolicy {
    pub chains: BTreeMap<dtos::ForeignChain, NonEmptyBTreeSet<dtos::RpcProvider>>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ForeignChainPolicyVotes {
    proposal_by_account: IterableMap<dtos::AccountId, ForeignChainPolicy>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    foreign_chain_policy: ForeignChainPolicy,
    foreign_chain_policy_votes: ForeignChainPolicyVotes,
    node_foreign_chain_configurations: NodeForeignChainConfigurations,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: OldStaleData,
    metrics: dtos::Metrics,
}

impl From<OldParticipantInfo> for ParticipantInfo {
    fn from(old: OldParticipantInfo) -> Self {
        // Participants' TLS keys are always Ed25519 by construction (enforced
        // by the TLS stack). Panicking here is safer than silently dropping
        // the entry: a participant with a non-Ed25519 key can never reach
        // this migration in practice, and dropping would break
        // `Participants::validate()` invariants (ID contiguity, threshold vs
        // size) and brick the contract.
        let tls_public_key = Ed25519PublicKey::try_from(&old.sign_pk)
            .expect("participant tls public key must be Ed25519");
        ParticipantInfo {
            url: old.url,
            tls_public_key,
        }
    }
}

impl From<OldParticipants> for Participants {
    fn from(old: OldParticipants) -> Self {
        let participants = old
            .participants
            .into_iter()
            .map(|(account_id, id, info)| (account_id, id, info.into()))
            .collect();
        Participants::init(old.next_id, participants)
    }
}

impl From<OldThresholdParameters> for ThresholdParameters {
    fn from(old: OldThresholdParameters) -> Self {
        ThresholdParameters::new_unvalidated(old.participants.into(), old.threshold)
    }
}

impl From<OldThresholdParametersVotes> for ThresholdParametersVotes {
    fn from(old: OldThresholdParametersVotes) -> Self {
        let proposal_by_account = old
            .proposal_by_account
            .into_iter()
            .map(|(account, params)| (account, params.into()))
            .collect();
        ThresholdParametersVotes {
            proposal_by_account,
        }
    }
}

impl From<OldKeyEvent> for KeyEvent {
    fn from(old: OldKeyEvent) -> Self {
        KeyEvent::from_raw(
            old.epoch_id,
            old.domain,
            old.parameters.into(),
            old.instance,
            old.next_attempt_id,
        )
    }
}

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters.into(),
            parameters_votes: old.parameters_votes.into(),
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

impl From<OldInitializingContractState> for InitializingContractState {
    fn from(old: OldInitializingContractState) -> Self {
        InitializingContractState {
            domains: old.domains,
            epoch_id: old.epoch_id,
            generated_keys: old.generated_keys,
            generating_key: old.generating_key.into(),
            cancel_votes: old.cancel_votes,
        }
    }
}

impl From<OldResharingContractState> for ResharingContractState {
    fn from(old: OldResharingContractState) -> Self {
        ResharingContractState {
            previous_running_state: old.previous_running_state.into(),
            reshared_keys: old.reshared_keys,
            resharing_key: old.resharing_key.into(),
            cancellation_requests: old.cancellation_requests,
        }
    }
}

impl From<OldProtocolContractState> for ProtocolContractState {
    fn from(old: OldProtocolContractState) -> Self {
        match old {
            OldProtocolContractState::NotInitialized => ProtocolContractState::NotInitialized,
            OldProtocolContractState::Initializing(state) => {
                ProtocolContractState::Initializing(state.into())
            }
            OldProtocolContractState::Running(state) => {
                ProtocolContractState::Running(state.into())
            }
            OldProtocolContractState::Resharing(state) => {
                ProtocolContractState::Resharing(state.into())
            }
        }
    }
}

impl From<MpcContract> for crate::MpcContract {
    fn from(mut value: MpcContract) -> Self {
        if !matches!(value.protocol_state, OldProtocolContractState::Running(_)) {
            env::panic_str("Contract must be in running state when migrating.");
        }

        value.foreign_chain_policy_votes.proposal_by_account.clear();

        let mut node_foreign_chain_support = SupportedForeignChainsByNode::default();

        value
            .node_foreign_chain_configurations
            .foreign_chain_configuration_by_node
            .drain()
            .for_each(|(account_id, foreign_chain_config)| {
                let supported_chains = foreign_chain_config
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .into();

                node_foreign_chain_support
                    .foreign_chain_support_by_node
                    .insert(account_id, supported_chains);
            });

        Self {
            protocol_state: value.protocol_state.into(),
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            node_foreign_chain_support,
            config: value.config,
            tee_state: value.tee_state.into(),
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: crate::StaleData {},
            metrics: value.metrics,
        }
    }
}

/// Previous `StaleData` layout — held a [`LookupMap`] of pre-upgrade signature requests.
/// After the v3.9 migration is fully deployed those requests have been resolved or timed
/// out, so the field is dropped here and the new `StaleData` is empty.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldStaleData {
    pending_signature_requests_pre_upgrade: LookupMap<SignatureRequest, YieldIndex>,
}

/// Previous `TeeState` layout — `stored_attestations` was an `IterableMap`
/// keyed by `near_sdk::PublicKey` (TLS key with curve tag) and held
/// [`OldNodeAttestation`]. The new layout keys by raw [`Ed25519PublicKey`]
/// and stores [`NodeAttestation`] with non-optional account keys.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: AllowedDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: CodeHashesVotes,
    launcher_votes: LauncherHashVotes,
    stored_attestations: IterableMap<near_sdk::PublicKey, OldNodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: MeasurementVotes,
}

impl Default for OldTeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: Default::default(),
            allowed_launcher_images: Default::default(),
            votes: Default::default(),
            launcher_votes: Default::default(),
            stored_attestations: IterableMap::new(StorageKey::StoredAttestations),
            allowed_measurements: Default::default(),
            measurement_votes: Default::default(),
        }
    }
}

impl From<OldTeeState> for TeeState {
    fn from(mut old: OldTeeState) -> Self {
        // Drain the old IterableMap to clear its on-chain entries before we
        // populate a fresh IterableMap under the same `StoredAttestations`
        // storage key. Without draining, leftover entries written under the
        // old `near_sdk::PublicKey` borsh encoding would collide with the new
        // `Ed25519PublicKey`-keyed entries.
        //
        // We migrate entry-by-entry: skip any whose TLS key is not Ed25519,
        // whose `account_public_key` is missing, or whose `account_public_key`
        // is not Ed25519. A stored non-Ed25519 TLS key could never match the
        // node's actual key (the contract always signed with Ed25519), so
        // dropping it is safe — we prefer silent skip over panic to avoid
        // bricking the migration transaction on pathological stored state.
        let drained: Vec<(near_sdk::PublicKey, OldNodeAttestation)> =
            old.stored_attestations.drain().collect();

        let mut new = TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: old.votes,
            launcher_votes: old.launcher_votes,
            stored_attestations: near_sdk::store::IterableMap::new(StorageKey::StoredAttestations),
            allowed_measurements: old.allowed_measurements,
            measurement_votes: old.measurement_votes,
        };

        for (tls_pk, old_attestation) in drained {
            let Some(new_tls_key) = dtos::Ed25519PublicKey::try_from(&tls_pk).ok() else {
                continue;
            };
            let Some(account_public_key) = old_attestation
                .node_id
                .account_public_key
                .as_ref()
                .and_then(|pk| dtos::Ed25519PublicKey::try_from(pk).ok())
            else {
                continue;
            };
            let node_id = dtos::NodeId {
                account_id: old_attestation.node_id.account_id,
                tls_public_key: new_tls_key.clone(),
                account_public_key,
            };
            new.stored_attestations.insert(
                new_tls_key,
                NodeAttestation {
                    node_id,
                    verified_attestation: old_attestation.verified_attestation,
                },
            );
        }

        new
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: OldNodeId,
    verified_attestation: VerifiedAttestation,
}

/// Previous `NodeId` layout — `tls_public_key` and `account_public_key` used the
/// `near_sdk::PublicKey` tagged borsh encoding. The new layout stores the TLS
/// key as a raw 32-byte [`dtos::Ed25519PublicKey`] and the account key as a
/// non-optional [`dtos::Ed25519PublicKey`], so we need a dedicated
/// pre-migration type here.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeId {
    account_id: AccountId,
    tls_public_key: near_sdk::PublicKey,
    account_public_key: Option<near_sdk::PublicKey>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_attestation::attestation::MockAttestation;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

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
        testing_env!(VMContextBuilder::new().build());
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
            dtos::Ed25519PublicKey::from([8u8; 32])
        );
    }

    #[test]
    fn tee_state_migration__should_skip_missing_account_key() {
        // Given a legacy/mock node that never recorded an account key
        testing_env!(VMContextBuilder::new().build());
        let tls_pk = old_ed25519_near_pk(1);
        let mut old = OldTeeState::default();
        old.stored_attestations
            .insert(tls_pk.clone(), old_attestation("bob.near", tls_pk, None));

        // When
        let new: TeeState = old.into();

        // Then the entry is dropped — NodeId can no longer represent a missing key
        assert!(new.stored_attestations.is_empty());
    }

    #[test]
    fn tee_state_migration__should_skip_entries_with_non_ed25519_tls_key() {
        // Given one Ed25519 entry and one secp256k1 entry in the old state
        testing_env!(VMContextBuilder::new().build());
        let good_tls = old_ed25519_near_pk(4);
        let bad_tls = old_secp256k1_near_pk(5);
        let account_pk = old_ed25519_near_pk(6);
        let mut old = OldTeeState::default();
        old.stored_attestations.insert(
            good_tls.clone(),
            old_attestation("good.near", good_tls, Some(account_pk.clone())),
        );
        old.stored_attestations.insert(
            bad_tls.clone(),
            old_attestation("bad.near", bad_tls, Some(account_pk)),
        );

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
        testing_env!(VMContextBuilder::new().build());
        let tls_pk = old_ed25519_near_pk(2);
        let secp_account_pk = old_secp256k1_near_pk(3);
        let mut old = OldTeeState::default();
        old.stored_attestations.insert(
            tls_pk.clone(),
            old_attestation("x.near", tls_pk, Some(secp_account_pk)),
        );

        // When
        let new: TeeState = old.into();

        // Then the entry is dropped entirely
        assert!(new.stored_attestations.is_empty());
    }

    fn old_participants(
        next_id: u32,
        entries: Vec<(&str, u32, near_sdk::PublicKey)>,
    ) -> OldParticipants {
        let participants = entries
            .into_iter()
            .map(|(account_id, pid, sign_pk)| {
                (
                    account_id.parse::<AccountId>().unwrap(),
                    ParticipantId(pid),
                    OldParticipantInfo {
                        url: "https://example.near".to_string(),
                        sign_pk,
                    },
                )
            })
            .collect();
        OldParticipants {
            next_id: ParticipantId(next_id),
            participants,
        }
    }

    fn old_running_state(participants: OldParticipants, threshold: u64) -> OldRunningContractState {
        let parameters = OldThresholdParameters {
            participants,
            threshold: Threshold(threshold),
        };
        OldRunningContractState {
            domains: DomainRegistry::default(),
            keyset: Keyset::new(EpochId::new(0), vec![]),
            parameters,
            parameters_votes: OldThresholdParametersVotes {
                proposal_by_account: BTreeMap::new(),
            },
            add_domains_votes: AddDomainsVotes::default(),
            previously_cancelled_resharing_epoch_id: None,
        }
    }

    #[test]
    fn participant_info_migration__should_rekey_ed25519_sign_pk_to_tls_public_key() {
        // Given
        let old = OldParticipantInfo {
            url: "https://alice.near".to_string(),
            sign_pk: old_ed25519_near_pk(5),
        };

        // When
        let new: ParticipantInfo = old.into();

        // Then
        assert_eq!(new.url, "https://alice.near");
        assert_eq!(new.tls_public_key, Ed25519PublicKey::from([5u8; 32]));
    }

    #[test]
    #[should_panic(expected = "participant tls public key must be Ed25519")]
    fn participant_info_migration__should_panic_on_non_ed25519_sign_pk() {
        // Given a participant with an unexpected secp256k1 sign_pk
        let old = OldParticipantInfo {
            url: "https://bad.near".to_string(),
            sign_pk: old_secp256k1_near_pk(6),
        };

        // When migrating (should panic)
        let _: ParticipantInfo = old.into();
    }

    #[test]
    fn protocol_state_migration__should_round_trip_running_state_through_borsh() {
        // Given a minimal Running state with one participant in the old layout
        let participants = old_participants(1, vec![("alice.near", 0, old_ed25519_near_pk(2))]);
        let running = old_running_state(participants, 2);
        let old_state = OldProtocolContractState::Running(running);
        let bytes = borsh::to_vec(&old_state).unwrap();

        // When borsh-decoding and migrating to the new layout
        let decoded: OldProtocolContractState = borsh::from_slice(&bytes).unwrap();
        let migrated: ProtocolContractState = decoded.into();

        // Then the migrated participant exposes tls_public_key with the Ed25519 bytes
        let ProtocolContractState::Running(state) = migrated else {
            panic!("expected Running state");
        };
        let participants = state.parameters.participants().participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(
            participants[0].2.tls_public_key,
            Ed25519PublicKey::from([2u8; 32])
        );
    }
}
