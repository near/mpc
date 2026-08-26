//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::VerifyForeignTransactionRequest;
use near_sdk::{
    AccountId, env,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    crypto_shared::types::{PublicKeyExtended, serializable::SerializableEdwardsPoint},
    foreign_chains_metadata::{ForeignChainsMetadata, SupportedForeignChainsByNode},
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        signature::{SignatureRequest, YieldIndex},
        threshold_votes::GovernanceThresholdParametersVotes,
        thresholds::GovernanceThresholdParameters,
    },
    state::{
        ProtocolContractState, initializing::InitializingContractState,
        resharing::ResharingContractState, running::RunningContractState,
    },
    storage_keys::StorageKey,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};
use near_mpc_contract_interface::types as dtos;

/// Shadow of the `3.14.0` [`Config`]: the deployed layout predates this release's
/// `attestation_storage_fee_millinear`, so migrating `3.14.0` state deserializes the old
/// field set and defaults the new one.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldConfig {
    key_event_timeout_blocks: u64,
    tee_upgrade_deadline_duration_seconds: u64,
    contract_upgrade_deposit_tera_gas: u64,
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
}

impl From<OldConfig> for Config {
    fn from(old: OldConfig) -> Self {
        // Deployed values carry forward, except `clean_invalid_attestations_tera_gas`: the
        // deployed 10 TGas is consumed by the scan itself, so the first eviction overruns it
        // and the detached sweep rolls back unnoticed. Taking the new default applies the fix
        // without a governance vote.
        Config {
            key_event_timeout_blocks: old.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: old.tee_upgrade_deadline_duration_seconds,
            contract_upgrade_deposit_tera_gas: old.contract_upgrade_deposit_tera_gas,
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
            clean_invalid_attestations_tera_gas: Config::default()
                .clean_invalid_attestations_tera_gas,
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
            // `attestation_storage_fee_millinear` is new in this release, so it defaults.
            ..Default::default()
        }
    }
}

/// Shadow of the `3.14.0` [`PublicKeyExtended`]: the deployed variants store the keys as
/// [`near_sdk::PublicKey`], which borsh-encodes as a length-prefixed `Vec<u8>` carrying a
/// curve-type byte, and the BLS variant stores the whole [`dtos::PublicKey`] enum. This
/// release stores the DTO key types directly, so every stored key changes layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldPublicKeyExtended {
    Secp256k1 {
        near_public_key: near_sdk::PublicKey,
    },
    Ed25519 {
        near_public_key_compressed: near_sdk::PublicKey,
        edwards_point: SerializableEdwardsPoint,
    },
    Bls12381 {
        public_key: dtos::PublicKey,
    },
}

/// The `3.14.0` contract validated the curve when the key was voted in, so the panics below
/// are unreachable for genuine state; they exist so a layout mismatch aborts the migration
/// instead of writing a mangled key.
impl From<OldPublicKeyExtended> for PublicKeyExtended {
    fn from(old: OldPublicKeyExtended) -> Self {
        match old {
            OldPublicKeyExtended::Secp256k1 { near_public_key } => PublicKeyExtended::Secp256k1 {
                near_public_key: dtos::Secp256k1PublicKey::try_from(&near_public_key)
                    .unwrap_or_else(|_| env::panic_str("Stored key is not a secp256k1 key.")),
            },
            OldPublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                edwards_point,
            } => PublicKeyExtended::Ed25519 {
                near_public_key_compressed: dtos::Ed25519PublicKey::try_from(
                    &near_public_key_compressed,
                )
                .unwrap_or_else(|_| env::panic_str("Stored key is not an ed25519 key.")),
                edwards_point,
            },
            OldPublicKeyExtended::Bls12381 { public_key } => {
                let dtos::PublicKey::Bls12381(public_key) = public_key else {
                    env::panic_str("Stored key is not a bls12381 key.");
                };
                PublicKeyExtended::Bls12381 { public_key }
            }
        }
    }
}

/// Shadow of the `3.14.0` [`KeyForDomain`], carrying [`OldPublicKeyExtended`].
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldKeyForDomain {
    domain_id: dtos::DomainId,
    key: OldPublicKeyExtended,
    attempt: AttemptId,
}

impl From<OldKeyForDomain> for KeyForDomain {
    fn from(old: OldKeyForDomain) -> Self {
        KeyForDomain {
            domain_id: old.domain_id,
            key: old.key.into(),
            attempt: old.attempt,
        }
    }
}

/// Shadow of the `3.14.0` [`Keyset`], carrying [`OldKeyForDomain`].
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldKeyset {
    epoch_id: EpochId,
    domains: Vec<OldKeyForDomain>,
}

impl From<OldKeyset> for Keyset {
    fn from(old: OldKeyset) -> Self {
        Keyset::new(
            old.epoch_id,
            old.domains.into_iter().map(Into::into).collect(),
        )
    }
}

/// Shadow of the `3.14.0` [`RunningContractState`]: only `keyset` changes layout, every
/// other field is byte-identical and reuses the current type.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: OldKeyset,
    parameters: GovernanceThresholdParameters,
    parameters_votes: GovernanceThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        RunningContractState {
            domains: old.domains,
            keyset: old.keyset.into(),
            parameters: old.parameters,
            parameters_votes: old.parameters_votes,
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// Shadow of the `3.14.0` [`ProtocolContractState`]. Only the `Running` variant has a
/// verified shadow: Initializing/Resharing reuse current types and would fail to
/// deserialize old data, which matches the pre-existing "migration panics if not Running"
/// policy enforced in [`From<MpcContract>`](MpcContract).
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(ResharingContractState),
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.14.0` contract still deserializes during migration.
///
/// `protocol_state` carries the public-key layout shift (#1246) and is shadowed by
/// `OldProtocolContractState`; `config` gains a field and is shadowed by `OldConfig`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    /// The deployed `3.14.0` keys predate `expected_payload_hash`, so this type parameter
    /// does not describe their borsh layout — do not read entries through this map. Not
    /// shadowed because `LookupMap`'s own borsh form is just the storage prefix: the type
    /// parameters never touch the state deserialization this struct exists for, and the
    /// migration discards the map unread.
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: OldConfig,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    metrics: Metrics,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: Option<AccountId>,
    tee_verifier_votes: TeeVerifierVotes,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        let OldProtocolContractState::Running(running) = old.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        crate::MpcContract {
            protocol_state: ProtocolContractState::Running(running.into()),
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            // `VerifyForeignTransactionRequest` gained `expected_payload_hash`, changing the
            // borsh key encoding, so entries pending at upgrade time are abandoned; their
            // yielded promises time out on chain as if never responded to. The abandoned V2 entries
            // are no longer addressable, so their storage staking is never reclaimed
            // (bounded by the number of requests in flight at upgrade time).
            pending_verify_foreign_tx_requests: LookupMap::new(
                crate::storage_keys::StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config.into(),
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        }
    }
}

/// Unused signature counters, dropped by the migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct Metrics {
    sign_with_v1_payload_count: u64,
    sign_with_v2_payload_count: u64,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::bogus_ed25519_public_key_extended;
    use rstest::rstest;

    /// Returns an old-layout key together with the key material it must migrate to.
    fn old_ed25519_key() -> (OldPublicKeyExtended, dtos::PublicKey) {
        let PublicKeyExtended::Ed25519 {
            near_public_key_compressed,
            edwards_point,
        } = bogus_ed25519_public_key_extended()
        else {
            unreachable!("helper always builds an ed25519 key")
        };

        let old = OldPublicKeyExtended::Ed25519 {
            near_public_key_compressed: near_sdk::PublicKey::from(
                near_public_key_compressed.clone(),
            ),
            edwards_point,
        };
        (old, dtos::PublicKey::Ed25519(near_public_key_compressed))
    }

    fn old_secp256k1_key() -> (OldPublicKeyExtended, dtos::PublicKey) {
        let key = dtos::Secp256k1PublicKey([3u8; 64]);
        let old = OldPublicKeyExtended::Secp256k1 {
            near_public_key: near_sdk::PublicKey::from(key.clone()),
        };
        (old, dtos::PublicKey::Secp256k1(key))
    }

    fn old_bls12381_key() -> (OldPublicKeyExtended, dtos::PublicKey) {
        let key = dtos::Bls12381G2PublicKey([5u8; 96]);
        let old = OldPublicKeyExtended::Bls12381 {
            public_key: dtos::PublicKey::Bls12381(key.clone()),
        };
        (old, dtos::PublicKey::Bls12381(key))
    }

    /// The migration must reproduce the exact key bytes the `3.14.0` contract stored, for
    /// every curve. `Bls12381` has no other coverage: the sandbox upgrade tests only add a
    /// CKD domain after the upgrade, so no BLS key crosses the migration there.
    #[rstest]
    #[case::secp256k1(old_secp256k1_key())]
    #[case::ed25519(old_ed25519_key())]
    #[case::bls12381(old_bls12381_key())]
    fn old_public_key_extended__should_migrate_to_the_same_key(
        #[case] (old, expected): (OldPublicKeyExtended, dtos::PublicKey),
    ) {
        // Given the old-layout bytes as the `3.14.0` contract wrote them.
        let bytes = borsh::to_vec(&old).unwrap();

        // When decoding through the shadow type and running the migration.
        let decoded: OldPublicKeyExtended = borsh::from_slice(&bytes).unwrap();
        let migrated: PublicKeyExtended = decoded.into();

        // Then the key material is unchanged.
        assert_eq!(dtos::PublicKey::from(migrated), expected);
    }
}
