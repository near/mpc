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
        key_state::{AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, Keyset},
        threshold_votes::GovernanceThresholdParametersVotes,
        thresholds::{GovernanceThresholdParameters, ProposedGovernanceThresholdParameters},
        votes::Votes,
    },
    state::{
        ProtocolContractState, initializing::InitializingContractState,
        running::RunningContractState,
    },
    storage_keys::StorageKey,
    tee::{
        measurements::AllowedMeasurements,
        proposal::{AllowedLauncherImages, StoredDockerImageHashes},
        tee_state::{NodeAttestation, TeeState},
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
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, NodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: OldMeasurementVotes,
}

impl From<OldTeeState> for TeeState {
    fn from(old: OldTeeState) -> Self {
        // Pending votes are dropped rather than migrated; participants re-vote after the
        // upgrade.
        TeeState {
            allowed_docker_image_hashes: old.allowed_docker_image_hashes,
            allowed_launcher_images: old.allowed_launcher_images,
            votes: old.votes,
            launcher_votes: Votes::new(
                StorageKey::LauncherHashVotesByVoter,
                StorageKey::LauncherHashVotesByProposal,
            ),
            stored_attestations: old.stored_attestations,
            allowed_measurements: old.allowed_measurements,
            measurement_votes: Votes::new(
                StorageKey::MeasurementVotesByVoter,
                StorageKey::MeasurementVotesByProposal,
            ),
        }
    }
}

/// Shadow of the `3.17.0` `GovernanceThresholdParametersVotes` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldGovernanceThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, ProposedGovernanceThresholdParameters>,
}

/// Shadow of the `3.17.0` `RunningContractState` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: GovernanceThresholdParameters,
    parameters_votes: OldGovernanceThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        // Pending parameter votes are dropped rather than migrated; participants re-vote
        // after the upgrade.
        RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters,
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// Shadow of the `3.17.0` `ProtocolContractState` layout. Only `Running` is migrated, so
/// the trailing `Resharing` variant is omitted and fails to deserialize.
#[expect(clippy::large_enum_variant)]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.17.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
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
        let OldProtocolContractState::Running(running_state) = old.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        crate::MpcContract {
            protocol_state: ProtocolContractState::Running(running_state.into()),
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            contract_update_votes: old.contract_update_votes,
            config: old.config,
            tee_state: old.tee_state.into(),
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
            parameters_votes: GovernanceThresholdParametersVotes::default(),
        }
    }
}
