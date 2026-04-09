//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::BTreeSet;

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
    Config, ForeignChainPolicyVotes, ForeignChainSupport, IntoInterfaceType, StaleData,
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
    config: Config,
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

        let mut foreign_chain_support = ForeignChainSupport::default();

        let participant_account_ids = running_state
            .parameters
            .participants()
            .participants()
            .iter()
            .cloned()
            .map(|(account_id, _, _)| account_id.into_dto_type());

        let supported_foreign_chains: BTreeSet<dtos::ForeignChain> =
            foreign_chain_policy.chains.keys().copied().collect();

        for account_id in participant_account_ids {
            foreign_chain_support
                .votes_per_chain
                .insert(account_id, supported_foreign_chains.clone().into());
        }

        // Overlay pending votes: if a participant had proposed a different policy,
        // merge their proposed chains into their baseline so their intent is preserved.
        for (voter_account_id, proposed_policy) in
            value.foreign_chain_policy_votes.proposal_by_account.iter()
        {
            let voter_proposed_chains: BTreeSet<dtos::ForeignChain> =
                proposed_policy.chains.keys().copied().collect();
            foreign_chain_support
                .votes_per_chain
                .entry(voter_account_id.clone())
                .and_modify(|existing| {
                    existing.extend(voter_proposed_chains.clone());
                })
                .or_insert_with(|| voter_proposed_chains.into());
        }
        Self {
            protocol_state: value.protocol_state,
            pending_signature_requests: value.pending_signature_requests,
            pending_ckd_requests: value.pending_ckd_requests,
            pending_verify_foreign_tx_requests: value.pending_verify_foreign_tx_requests,
            proposed_updates: value.proposed_updates,
            foreign_chain_policy,
            foreign_chain_policy_votes: value.foreign_chain_policy_votes,
            config: value.config,
            tee_state: value.tee_state,
            accept_requests: value.accept_requests,
            node_migrations: value.node_migrations,
            stale_data: value.stale_data,
            metrics: value.metrics,
            supported_foreign_chains_votes: foreign_chain_support,
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use near_mpc_bounded_collections::NonEmptyBTreeSet;

    use super::*;

    #[expect(deprecated)]
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

    #[expect(deprecated)]
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

    #[expect(deprecated)]
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

    #[expect(deprecated)]
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
