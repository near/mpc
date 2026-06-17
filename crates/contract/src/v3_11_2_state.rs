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
use near_mpc_contract_interface::types::{Metrics, VerifyForeignTransactionRequest};
use near_sdk::{env, store::LookupMap};

use crate::{
    Config, SupportedForeignChainsByNode,
    foreign_chain_rpc::ForeignChainRpcWhitelist,
    initial_tee_verifier_account_id,
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedAccountId, EpochId, Keyset},
        signature::{SignatureRequest, YieldIndex},
        threshold_votes::ThresholdParametersVotes,
        thresholds::ThresholdParameters,
    },
    state::{
        ProtocolContractState, initializing::InitializingContractState,
        resharing::ResharingContractState, running::RunningContractState,
    },
    storage_keys::StorageKey,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};

/// `3.11.2` layout of `ThresholdParametersVotes`. The stored
/// `ThresholdParameters` (`{ participants, threshold }`) is byte-identical
/// between 3.11.2 and the current layout, so no shadow is needed for it — the
/// real type decodes old bytes directly. Only the vote *value* type changed:
/// votes now carry [`ProposedThresholdParameters`], which appends a
/// `per_domain_thresholds` map. We still need this shadow to consume the old
/// positional vote bytes, but the migration **drops** all pending votes rather
/// than carrying them forward.
///
/// Carrying them forward isn't faithful: old resharing reset every domain's
/// reconstruction threshold to the (global) governance threshold, so a correct
/// migration would have to materialize that per-domain — not the "keep current
/// thresholds" that an empty map denotes. Reconstructing the historically
/// correct value isn't worth the complexity. Dropping in-flight votes is
/// operationally fine: voters simply resubmit `vote_new_parameters` after the
/// upgrade.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, ThresholdParameters>,
}

impl From<OldThresholdParametersVotes> for ThresholdParametersVotes {
    /// Drops all pending parameter-change votes on migration. See
    /// [`OldThresholdParametersVotes`] for why we don't carry them forward.
    fn from(_old: OldThresholdParametersVotes) -> Self {
        ThresholdParametersVotes::default()
    }
}

/// `3.11.2` layout of `RunningContractState`. The stored `parameters` use the
/// real `ThresholdParameters` (byte-identical to 3.11.2); only `parameters_votes`
/// needs the [`OldThresholdParametersVotes`] shadow.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: ThresholdParameters,
    parameters_votes: OldThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl From<OldRunningContractState> for RunningContractState {
    fn from(old: OldRunningContractState) -> Self {
        RunningContractState {
            domains: old.domains,
            keyset: old.keyset,
            parameters: old.parameters,
            parameters_votes: old.parameters_votes.into(),
            add_domains_votes: old.add_domains_votes,
            previously_cancelled_resharing_epoch_id: old.previously_cancelled_resharing_epoch_id,
        }
    }
}

/// `3.11.2` layout of `ProtocolContractState`. Only the `Running` variant
/// has a verified shadow — Initializing/Resharing reuse current types and
/// would fail to deserialize old data, which matches the pre-existing
/// "migration panics if not Running" policy.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
enum OldProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(OldRunningContractState),
    Resharing(ResharingContractState),
}

/// Keep this module in lock-step with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.11.2` contract still deserializes during migration.
///
/// `protocol_state` carries the per-domain-threshold layout shift (#3169) and is shadowed
/// by `OldProtocolContractState`; every other field is byte-identical to `3.11.2`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    // Shadowed: the verifier integration added three gas fields to `crate::Config`,
    // so the deployed borsh layout differs from the current one.
    config: OldConfig,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    metrics: Metrics,
    foreign_chain_rpc_whitelist: ForeignChainRpcWhitelist,
}

/// The `Config` borsh layout deployed before the verifier integration added the
/// `verifier_tera_gas` / `resolve_verification_tera_gas` /
/// `on_attestation_verified_tera_gas` fields. Shadowed so deployed state still
/// deserializes; the conversion below fills the new fields from `Config`'s
/// defaults.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldConfig {
    key_event_timeout_blocks: u64,
    tee_upgrade_deadline_duration_seconds: u64,
    contract_upgrade_deposit_tera_gas: u64,
    sign_call_gas_attachment_requirement_tera_gas: u64,
    ckd_call_gas_attachment_requirement_tera_gas: u64,
    return_signature_and_clean_state_on_success_call_tera_gas: u64,
    return_ck_and_clean_state_on_success_call_tera_gas: u64,
    fail_on_timeout_tera_gas: u64,
    clean_tee_status_tera_gas: u64,
    clean_invalid_attestations_tera_gas: u64,
    cleanup_orphaned_node_migrations_tera_gas: u64,
    remove_non_participant_update_votes_tera_gas: u64,
    clean_foreign_chain_data_tera_gas: u64,
}

impl From<OldConfig> for Config {
    fn from(old: OldConfig) -> Self {
        // Start from defaults so the three new gas fields get sensible values,
        // then carry over every field that existed before.
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
            clean_tee_status_tera_gas: old.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: old.clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: old
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: old
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: old.clean_foreign_chain_data_tera_gas,
            ..Config::default()
        }
    }
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
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config.into(),
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            metrics: old.metrics,
            foreign_chain_rpc_whitelist: old.foreign_chain_rpc_whitelist,
            // No verifier was chosen by the pre-verifier contract: start from the
            // placeholder, empty votes, and an empty pending map. Participants
            // vote in a real verifier via `vote_tee_verifier_change`.
            tee_verifier_account_id: initial_tee_verifier_account_id(None),
            tee_verifier_votes: TeeVerifierVotes::default(),
            pending_attestations: LookupMap::new(StorageKey::PendingAttestationsV1),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::{NUM_PROTOCOLS, gen_participants};
    use crate::primitives::thresholds::Threshold;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    /// Migration drops any pending parameter-change votes. The old 3.11.2 votes
    /// carried bare `ThresholdParameters` with no per-domain thresholds; carrying
    /// them forward would require materializing per-domain thresholds (the old
    /// governance threshold for every domain), which isn't worth reconstructing —
    /// see [`OldThresholdParametersVotes`]. Voters simply resubmit after the upgrade.
    ///
    /// This decodes a non-empty old-layout votes map through the shadow type and
    /// asserts the migration yields an empty `ThresholdParametersVotes`, so it
    /// fails if either the old layout or the vote-dropping logic regresses.
    #[test]
    fn old_threshold_parameter_votes__should_be_dropped_on_migration() {
        // Given a participant set with one member installed as the signer, so we can
        // mint an `AuthenticatedAccountId` to key the vote by.
        let participants = gen_participants(NUM_PROTOCOLS);
        let n = participants.len() as u64;
        let voter_account = participants.participants()[0].0.clone();

        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(voter_account);
        testing_env!(ctx.build());
        let voter = AuthenticatedAccountId::new(&participants).unwrap();

        // and old-layout vote bytes: a single vote whose value is a bare
        // `ThresholdParameters` (the 3.11.2 vote shape).
        let params = ThresholdParameters::new(participants, Threshold::new(n)).unwrap();
        let old = OldThresholdParametersVotes {
            proposal_by_account: BTreeMap::from([(voter, params)]),
        };
        let bytes = borsh::to_vec(&old).unwrap();

        // When decoding through the shadow type and running the real migration.
        let decoded: OldThresholdParametersVotes = borsh::from_slice(&bytes).unwrap();
        let migrated: ThresholdParametersVotes = decoded.into();

        // Then all pending votes are dropped.
        assert!(migrated.proposal_by_account.is_empty());
    }
}
