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
use near_mpc_contract_interface::types::{self as dtos, VerifyForeignTransactionRequest};
use near_sdk::{env, store::LookupMap};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedAccountId, EpochId, Keyset},
        participants::Participants,
        signature::{SignatureRequest, YieldIndex},
        threshold_votes::ThresholdParametersVotes,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::{
        initializing::InitializingContractState, resharing::ResharingContractState,
        running::RunningContractState, ProtocolContractState,
    },
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    Config, SupportedForeignChainsByNode,
};

/// Pre-3.11 layout of `ThresholdParameters`. The new layout appends
/// `per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>`
/// (see #3169). Borsh is positional, so old bytes can be decoded into this
/// shadow and then mapped to the new struct with the map defaulted to empty.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldThresholdParameters {
    participants: Participants,
    threshold: Threshold,
}

impl From<OldThresholdParameters> for ThresholdParameters {
    fn from(old: OldThresholdParameters) -> Self {
        // Resharing votes from before this migration didn't carry per-domain
        // thresholds, so the migrated proposal preserves the existing
        // domains' thresholds (interpreted later as a no-change overlay).
        ThresholdParameters::new_unvalidated(old.participants, old.threshold)
    }
}

/// Pre-3.11 layout of `ThresholdParametersVotes` — same shape but with the
/// old `OldThresholdParameters` as the value type.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, OldThresholdParameters>,
}

impl From<OldThresholdParametersVotes> for ThresholdParametersVotes {
    fn from(old: OldThresholdParametersVotes) -> Self {
        ThresholdParametersVotes {
            proposal_by_account: old
                .proposal_by_account
                .into_iter()
                .map(|(acc, params)| (acc, params.into()))
                .collect(),
        }
    }
}

/// Pre-3.11 layout of `RunningContractState`. Mirrors the current shape but
/// uses the old `OldThresholdParameters` and `OldThresholdParametersVotes`.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldRunningContractState {
    domains: DomainRegistry,
    keyset: Keyset,
    parameters: OldThresholdParameters,
    parameters_votes: OldThresholdParametersVotes,
    add_domains_votes: AddDomainsVotes,
    previously_cancelled_resharing_epoch_id: Option<EpochId>,
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

/// Pre-3.11 layout of `ProtocolContractState`. Only the `Running` variant
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

/// In-flight requests inherited from the schema before the duplicate-request fan-out
/// upgrade. Kept inlined here (rather than imported) so storage written by the 3.10
/// contract still deserializes during migration. Dropped in the `From` impl below
/// because the legacy window has closed.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct LegacyPendingRequests {
    signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, YieldIndex>,
}

/// `3.10.0`'s `MpcContract` layout, plus the per-domain-threshold layout shift
/// in `protocol_state` (#3169). The trailing `foreign_chain_rpc_whitelist`
/// uses the pre-reshape `OldForeignChainRpcWhitelist` and `legacy_pending_requests`
/// retains its 3.10 borsh shape; both are discarded in the `From` impl.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: OldProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests:
        LookupMap<dtos::VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    legacy_pending_requests: LegacyPendingRequests,
    metrics: dtos::Metrics,
    foreign_chain_rpc_whitelist: OldForeignChainRpcWhitelist,
}

/// `3.10.0`'s whitelist field shape: a single nested `BTreeMap`, no vote storage. The
/// `From` impl above discards it and default-initializes the current whitelist because
/// `3.10.0` had no vote endpoint and so the map is guaranteed empty.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldForeignChainRpcWhitelist {
    entries: BTreeMap<dtos::ForeignChain, BTreeMap<dtos::ProviderId, OldProviderEntry>>,
}

/// Local shadow of `3.10.0`'s `ProviderEntry` borsh shape. The current revision renamed
/// the public DTO to `ProviderConfig` and dropped the `provider_id` field (it became the
/// map key), so the public DTO no longer matches `3.10.0`'s on-disk bytes. `3.10.0`
/// guarantees the outer map is empty, so this inner type is never actually deserialized
/// — but the parent `BTreeMap<ProviderId, _>` still needs a concrete `V: BorshDeserialize`
/// to satisfy the type bound on the derive.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OldProviderEntry {
    provider_id: dtos::ProviderId,
    base_url: String,
    auth_scheme: dtos::AuthScheme,
    chain_routing: dtos::ChainRouting,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        let OldProtocolContractState::Running(running) = old.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        // `3.10.0` had no vote endpoint, so `old.foreign_chain_rpc_whitelist.entries`
        // is guaranteed empty — drop it and default-initialize the current reshaped
        // whitelist (empty `entries`, empty `votes.pending`). `legacy_pending_requests`
        // is also discarded: the field was removed from `crate::MpcContract` (#3279)
        // and the legacy window has closed.
        crate::MpcContract {
            protocol_state: ProtocolContractState::Running(running.into()),
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            proposed_updates: old.proposed_updates,
            node_foreign_chain_support: old.node_foreign_chain_support,
            config: old.config,
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            metrics: old.metrics,
            foreign_chain_rpc_whitelist: Default::default(),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::{gen_participants, NUM_PROTOCOLS};

    /// Borsh round-trip: write a `ThresholdParameters` in the OLD layout
    /// (no `per_domain_thresholds` field), deserialize via the shadow,
    /// convert to the new struct, and assert the overlay defaults to empty.
    #[test]
    fn old_threshold_parameters__should_deserialize_into_empty_overlay() {
        // Given old-layout bytes
        let participants = gen_participants(NUM_PROTOCOLS);
        let n = participants.len() as u64;
        let old = OldThresholdParameters {
            participants,
            threshold: Threshold::new(n),
        };
        let bytes = borsh::to_vec(&old).unwrap();

        // When borsh-decoding through the shadow and migrating
        let decoded: OldThresholdParameters = borsh::from_slice(&bytes).unwrap();
        let migrated: ThresholdParameters = decoded.into();

        // Then per-domain overlay is empty and core fields round-trip
        assert!(migrated.per_domain_thresholds().is_empty());
        assert_eq!(migrated.threshold().value(), n);
    }
}
