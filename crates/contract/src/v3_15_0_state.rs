//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
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
    state::ProtocolContractState,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ProposedUpdates,
};

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see this module's history for examples) so
/// state written by the `3.15.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    node_foreign_chain_support: OldSupportedForeignChainsByNode,
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
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
        }
    }
}

/// Shadow of the `3.15.0` legacy account-keyed support map; the migration clears it.
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
    use crate::storage_keys::StorageKey;
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
}
