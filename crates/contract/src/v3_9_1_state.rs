//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use dtos::{
    Curve, DomainConfig, DomainId, DomainPurpose, Ed25519PublicKey, ParticipantId, Protocol,
    ReconstructionThreshold, Threshold,
};
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
    state::{key_event::KeyEventInstance, running::RunningContractState, ProtocolContractState},
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

/// Previous `Curve` Borsh layout — included `V2Secp256k1` (variant index 3)
/// for Robust ECDSA. Kept here so the migration can decode legacy state that
/// was serialized before `V2Secp256k1` was removed; in the new representation,
/// it maps to `(Curve::Secp256k1, Protocol::DamgardEtAl)`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldCurve {
    Secp256k1,
    Edwards25519,
    Bls12381,
    V2Secp256k1,
}

/// Previous `DomainConfig` layout — `protocol` was not stored; it is now
/// derived from `curve` during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldDomainConfig {
    id: DomainId,
    curve: OldCurve,
    purpose: DomainPurpose,
}

/// Previous `DomainRegistry` Borsh layout — wraps `Vec<OldDomainConfig>`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldDomainRegistry {
    domains: Vec<OldDomainConfig>,
    next_domain_id: u64,
}

/// Previous `AddDomainsVotes` Borsh layout — stored old `DomainConfig`s.
/// Deserialize-only: kept solely to preserve the on-chain Borsh layout of
/// `OldRunningContractState`. The migration discards the contents (see the
/// `From<OldRunningContractState> for RunningContractState` impl below).
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldAddDomainsVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<OldDomainConfig>>,
}

/// Caller supplies the global threshold; legacy state had no per-domain value.
/// V2Secp256k1 (DamgardEtAl) was never deployed to production, so no
/// protocol-specific adjustment is required here — every legacy domain
/// inherits the global threshold uniformly.
fn migrate_domain_config(
    old: OldDomainConfig,
    reconstruction_threshold: ReconstructionThreshold,
) -> DomainConfig {
    let (curve, protocol) = match old.curve {
        OldCurve::Secp256k1 => (Curve::Secp256k1, Protocol::CaitSith),
        OldCurve::Edwards25519 => (Curve::Edwards25519, Protocol::Frost),
        OldCurve::Bls12381 => (Curve::Bls12381, Protocol::ConfidentialKeyDerivation),
        OldCurve::V2Secp256k1 => (Curve::Secp256k1, Protocol::DamgardEtAl),
    };
    DomainConfig {
        id: old.id,
        curve,
        protocol,
        reconstruction_threshold,
        purpose: old.purpose,
    }
}

fn migrate_domain_registry(
    old: OldDomainRegistry,
    reconstruction_threshold: ReconstructionThreshold,
) -> DomainRegistry {
    let domains: Vec<DomainConfig> = old
        .domains
        .into_iter()
        .map(|d| migrate_domain_config(d, reconstruction_threshold))
        .collect();
    // The on-chain DomainRegistry was previously valid by construction;
    // its invariants (id contiguity, monotonic next_domain_id) carry over.
    DomainRegistry::from_raw_validated(domains, old.next_domain_id)
        .expect("on-chain DomainRegistry should be valid")
}

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

impl From<NodeForeignChainConfigurations> for SupportedForeignChainsByNode {
    fn from(mut old: NodeForeignChainConfigurations) -> Self {
        // Drain the old IterableMap to clear its on-chain entries under
        // `_SupportedForeignChainsVotes` before populating the new map under
        // the distinct `SupportedForeignChainsByNode` storage key. Each entry's
        // `ForeignChainConfiguration` collapses to the set of its chain keys —
        // the RPC-provider list is dropped because the new layout no longer
        // tracks per-node RPC providers.
        let mut new = SupportedForeignChainsByNode::default();
        old.foreign_chain_configuration_by_node.drain().for_each(
            |(account_id, foreign_chain_config)| {
                let supported_chains = foreign_chain_config
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .into();
                new.foreign_chain_support_by_node
                    .insert(account_id, supported_chains);
            },
        );
        new
    }
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

/// Mirror of the current `KeyEvent` with `OldThresholdParameters` and
/// `OldDomainConfig` swapped in. `KeyEventInstance` does not transitively
/// contain `ParticipantInfo` or `DomainConfig`, so it is reused as-is.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldKeyEvent {
    epoch_id: EpochId,
    domain: OldDomainConfig,
    parameters: OldThresholdParameters,
    instance: Option<KeyEventInstance>,
    next_attempt_id: AttemptId,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: OldDomainRegistry,
    keyset: Keyset,
    parameters: OldThresholdParameters,
    parameters_votes: OldThresholdParametersVotes,
    add_domains_votes: OldAddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldInitializingContractState {
    domains: OldDomainRegistry,
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

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        let reconstruction_threshold = ReconstructionThreshold::from(old.parameters.threshold);
        RunningContractState {
            domains: migrate_domain_registry(old.domains, reconstruction_threshold),
            keyset: old.keyset,
            parameters: old.parameters.into(),
            parameters_votes: old.parameters_votes.into(),
            // Pending `add_domains_votes` are dropped: legacy entries didn't
            // carry a per-domain `reconstruction_threshold`, and stamping
            // them with the global threshold would cause post-migration
            // voters that recast with a different threshold to fail to
            // match — voters re-cast on a clean slate after the upgrade.
            add_domains_votes: AddDomainsVotes::default(),
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

impl From<MpcContract> for crate::MpcContract {
    fn from(mut value: MpcContract) -> Self {
        let OldProtocolContractState::Running(running) = value.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        value.foreign_chain_policy_votes.proposal_by_account.clear();

        Self {
            protocol_state: ProtocolContractState::Running(running.into()),
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            pending_attestations: near_sdk::store::IterableMap::new(
                crate::storage_keys::StorageKey::PendingAttestations,
            ),
            proposed_updates: value.proposed_updates,
            node_foreign_chain_support: value.node_foreign_chain_configurations.into(),
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
            domains: OldDomainRegistry {
                domains: vec![],
                next_domain_id: 0,
            },
            keyset: Keyset::new(EpochId::new(0), vec![]),
            parameters,
            parameters_votes: OldThresholdParametersVotes {
                proposal_by_account: BTreeMap::new(),
            },
            add_domains_votes: OldAddDomainsVotes {
                proposal_by_account: BTreeMap::new(),
            },
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
        let bytes = borsh::to_vec(&running).unwrap();

        // When borsh-decoding and migrating to the new layout
        let decoded: OldRunningContractState = borsh::from_slice(&bytes).unwrap();
        let migrated: RunningContractState = decoded.into();

        // Then the migrated participant exposes tls_public_key with the Ed25519 bytes
        let participants = migrated.parameters.participants().participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(
            participants[0].2.tls_public_key,
            Ed25519PublicKey::from([2u8; 32])
        );
    }

    impl Default for NodeForeignChainConfigurations {
        fn default() -> Self {
            Self {
                foreign_chain_configuration_by_node: IterableMap::new(
                    StorageKey::_SupportedForeignChainsVotes,
                ),
            }
        }
    }

    fn rpc_provider(url: &str) -> dtos::RpcProvider {
        dtos::RpcProvider {
            rpc_url: url.to_string(),
        }
    }

    #[expect(deprecated, reason = "ForeignChainConfiguration is being deprecated")]
    fn old_foreign_chain_configuration(
        chains: &[(dtos::ForeignChain, &str)],
    ) -> dtos::ForeignChainConfiguration {
        chains
            .iter()
            .map(|(chain, url)| (*chain, NonEmptyBTreeSet::new(rpc_provider(url))))
            .collect::<BTreeMap<_, _>>()
            .into()
    }

    fn supported_chains(
        chains: impl IntoIterator<Item = dtos::ForeignChain>,
    ) -> dtos::SupportedForeignChains {
        chains.into_iter().collect::<BTreeSet<_>>().into()
    }

    #[test]
    fn node_foreign_chain_configurations_migration__should_keep_chains_and_drop_rpc_providers() {
        // Given a node with multiple chains, each having an RPC provider
        testing_env!(VMContextBuilder::new().build());
        let account: dtos::AccountId = "alice.near".parse().unwrap();
        let mut old = NodeForeignChainConfigurations::default();
        old.foreign_chain_configuration_by_node.insert(
            account.clone(),
            old_foreign_chain_configuration(&[
                (dtos::ForeignChain::Bitcoin, "https://btc.example.com"),
                (dtos::ForeignChain::Ethereum, "https://eth.example.com"),
            ]),
        );

        // When migrating
        let new: SupportedForeignChainsByNode = old.into();

        // Then only the chain set survives — RPC providers are dropped
        let stored = new
            .foreign_chain_support_by_node
            .get(&account)
            .expect("entry was migrated");
        assert_eq!(
            *stored,
            supported_chains([dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum])
        );
    }

    #[test]
    fn node_foreign_chain_configurations_migration__should_preserve_per_node_chains() {
        // Given multiple nodes with different chain support
        testing_env!(VMContextBuilder::new().build());
        let alice: dtos::AccountId = "alice.near".parse().unwrap();
        let bob: dtos::AccountId = "bob.near".parse().unwrap();
        let mut old = NodeForeignChainConfigurations::default();
        old.foreign_chain_configuration_by_node.insert(
            alice.clone(),
            old_foreign_chain_configuration(&[(
                dtos::ForeignChain::Bitcoin,
                "https://btc.alice.near",
            )]),
        );
        old.foreign_chain_configuration_by_node.insert(
            bob.clone(),
            old_foreign_chain_configuration(&[
                (dtos::ForeignChain::Solana, "https://sol.bob.near"),
                (dtos::ForeignChain::Ethereum, "https://eth.bob.near"),
            ]),
        );

        // When migrating
        let new: SupportedForeignChainsByNode = old.into();

        // Then each node's chain set is preserved independently
        assert_eq!(new.foreign_chain_support_by_node.len(), 2);
        assert_eq!(
            *new.foreign_chain_support_by_node
                .get(&alice)
                .expect("alice migrated"),
            supported_chains([dtos::ForeignChain::Bitcoin]),
        );
        assert_eq!(
            *new.foreign_chain_support_by_node
                .get(&bob)
                .expect("bob migrated"),
            supported_chains([dtos::ForeignChain::Solana, dtos::ForeignChain::Ethereum]),
        );
    }

    #[test]
    fn node_foreign_chain_configurations_migration__should_be_empty_when_no_configurations() {
        // Given an empty configuration map
        testing_env!(VMContextBuilder::new().build());
        let old = NodeForeignChainConfigurations::default();

        // When migrating
        let new: SupportedForeignChainsByNode = old.into();

        // Then the migrated map is empty
        assert!(new.foreign_chain_support_by_node.is_empty());
    }
    #[test]
    fn domain_config_migration__should_derive_protocol_from_curve_and_inherit_threshold() {
        // Given OldDomainConfigs covering every legacy curve, including V2Secp256k1
        let cases = [
            (OldCurve::Secp256k1, Curve::Secp256k1, Protocol::CaitSith),
            (OldCurve::Edwards25519, Curve::Edwards25519, Protocol::Frost),
            (
                OldCurve::Bls12381,
                Curve::Bls12381,
                Protocol::ConfidentialKeyDerivation,
            ),
            (
                OldCurve::V2Secp256k1,
                Curve::Secp256k1,
                Protocol::DamgardEtAl,
            ),
        ];

        let global_threshold = ReconstructionThreshold::new(7);
        for (i, (old_curve, expected_curve, expected_protocol)) in cases.into_iter().enumerate() {
            let purpose = match expected_curve {
                Curve::Bls12381 => DomainPurpose::CKD,
                _ => DomainPurpose::Sign,
            };
            let old = OldDomainConfig {
                id: DomainId(i as u64),
                curve: old_curve,
                purpose,
            };
            let bytes = borsh::to_vec(&old).unwrap();

            // When borsh-decoding the old layout and converting to the new DomainConfig
            let decoded: OldDomainConfig = borsh::from_slice(&bytes).unwrap();
            let migrated = migrate_domain_config(decoded, global_threshold);

            // Then curve, protocol, and per-domain reconstruction threshold are set
            assert_eq!(migrated.curve, expected_curve);
            assert_eq!(migrated.protocol, expected_protocol);
            assert_eq!(migrated.id, DomainId(i as u64));
            assert_eq!(migrated.reconstruction_threshold, global_threshold);
        }
    }

    #[test]
    fn running_state_migration__should_copy_global_threshold_into_each_domain() {
        // Given a legacy running state with two domains and a global threshold
        testing_env!(VMContextBuilder::new().build());
        let participants = old_participants(1, vec![("alice.near", 0, old_ed25519_near_pk(2))]);
        let mut running = old_running_state(participants, 5);
        running.domains = OldDomainRegistry {
            domains: vec![
                OldDomainConfig {
                    id: DomainId(0),
                    curve: OldCurve::Secp256k1,
                    purpose: DomainPurpose::Sign,
                },
                OldDomainConfig {
                    id: DomainId(1),
                    curve: OldCurve::Edwards25519,
                    purpose: DomainPurpose::Sign,
                },
            ],
            next_domain_id: 2,
        };

        // When migrating
        let migrated: RunningContractState = running.into();

        // Then every migrated domain inherits the legacy global threshold
        let expected = ReconstructionThreshold::new(5);
        assert_eq!(migrated.domains.domains().len(), 2);
        for domain in migrated.domains.domains() {
            assert_eq!(domain.reconstruction_threshold, expected);
        }
    }
}
