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
    state::ProtocolContractState,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.16.0` contract still deserializes during migration.
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
    config: Config,
    tee_state: TeeState,
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

        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            config: old.config,
            tee_state: old.tee_state,
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
