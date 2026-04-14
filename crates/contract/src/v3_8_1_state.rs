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
use near_sdk::{env, store::LookupMap};

use crate::{
    node_migrations::NodeMigrations,
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    state::ProtocolContractState,
    tee::tee_state::TeeState,
    update::ProposedUpdates,
    ForeignChainPolicyVotes, IntoInterfaceType, NodeForeignChainConfigurations, StaleData,
};

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
    config: OldConfig,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    stale_data: StaleData,
    metrics: dtos::Metrics,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(value: MpcContract) -> Self {
        let crate::ProtocolContractState::Running(running_state) = &value.protocol_state else {
            env::panic_str("Contract must be in running state when migrating.");
        };

        let foreign_chain_policy = value.foreign_chain_policy;

        let mut foreign_chain_support = NodeForeignChainConfigurations::default();

        let participant_account_ids = running_state
            .parameters
            .participants()
            .participants()
            .iter()
            .cloned()
            .map(|(account_id, _, _)| account_id.into_dto_type());

        let current_on_chain_policy = foreign_chain_policy.chains.clone();

        for account_id in participant_account_ids {
            foreign_chain_support
                .foreign_chain_configuration_by_node
                .insert(account_id, current_on_chain_policy.clone().into());
        }

        // Overlay pending votes: if a participant had proposed a different policy,
        // merge their proposed chains into their baseline so their intent is preserved.
        for (voter_account_id, proposed_policy) in
            value.foreign_chain_policy_votes.proposal_by_account.iter()
        {
            foreign_chain_support
                .foreign_chain_configuration_by_node
                .insert(
                    voter_account_id.clone(),
                    proposed_policy.chains.clone().into(),
                );
        }
        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            config: value.config.into(),
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: value.stale_data,
            metrics: value.metrics,
            node_foreign_chain_configurations: foreign_chain_support,
        }
    }
}

/// Previous Config layout without `clean_foreign_chain_data_tera_gas`.
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
    clean_tee_status_tera_gas: u64,
    cleanup_orphaned_node_migrations_tera_gas: u64,
    remove_non_participant_update_votes_tera_gas: u64,
}

impl From<OldConfig> for crate::Config {
    fn from(old: OldConfig) -> Self {
        let defaults = crate::Config::default();
        crate::Config {
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
            cleanup_orphaned_node_migrations_tera_gas: old
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: old
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: defaults.clean_foreign_chain_data_tera_gas,
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeMap, BTreeSet};

    use near_mpc_bounded_collections::NonEmptyBTreeSet;

    use super::*;

    fn make_policy(chains: Vec<dtos::ForeignChain>) -> dtos::ForeignChainPolicy {
        dtos::ForeignChainPolicy {
            chains: chains
                .into_iter()
                .map(|chain| {
                    (
                        chain,
                        NonEmptyBTreeSet::new(dtos::RpcProvider {
                            rpc_url: "https://rpc.example.com".to_string(),
                        }),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn test_migration_derives_supported_foreign_chains_from_policy() {
        let policy = make_policy(vec![
            dtos::ForeignChain::Bitcoin,
            dtos::ForeignChain::Ethereum,
        ]);

        let supported: dtos::SupportedForeignChains = policy
            .chains
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            .into();

        assert!(supported.contains(&dtos::ForeignChain::Bitcoin));
        assert!(supported.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(supported.len(), 2);
    }

    #[test]
    fn test_migration_derives_empty_supported_foreign_chains_from_empty_policy() {
        let policy = dtos::ForeignChainPolicy {
            chains: BTreeMap::new(),
        };

        let supported: dtos::SupportedForeignChains = policy
            .chains
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into();

        assert!(supported.is_empty());
    }

    #[test]
    fn test_migration_supported_foreign_chains_preserves_all_chain_keys() {
        let all_chains = vec![
            dtos::ForeignChain::Solana,
            dtos::ForeignChain::Bitcoin,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Base,
            dtos::ForeignChain::Bnb,
            dtos::ForeignChain::Arbitrum,
        ];
        let policy = make_policy(all_chains.clone());

        let supported: dtos::SupportedForeignChains = policy
            .chains
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into();

        assert_eq!(supported.len(), all_chains.len());
        for chain in &all_chains {
            assert!(supported.contains(chain));
        }
    }
}
