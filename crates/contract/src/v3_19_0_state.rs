//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::hash::GenesisHash;
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
    primitives::threshold_votes::GovernanceThresholdParametersVotes,
    state::ProtocolContractState,
    tee::{tee_state::TeeState, verifier_votes::TeeVerifierVotes},
    update::ContractUpdateVotes,
};

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.19.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    contract_update_votes: ContractUpdateVotes,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: AccountId,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
    parameters_votes: GovernanceThresholdParametersVotes,
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
            contract_update_votes: old.contract_update_votes,
            config: old.config,
            tee_state: old.tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains: old.foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
            parameters_votes: old.parameters_votes,
            genesis_hash: genesis_hash_of(&env::chain_id()),
        }
    }
}

/// The `3.19.0` contract does not store the genesis hash of its chain. Its chain id tells the
/// genesis hash only for mainnet and testnet, so a contract on any other chain gets none.
fn genesis_hash_of(chain_id: &str) -> Option<GenesisHash> {
    match chain_id {
        "mainnet" => Some(GenesisHash::MAINNET),
        "testnet" => Some(GenesisHash::TESTNET),
        _ => None,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::mainnet("mainnet", Some(GenesisHash::MAINNET))]
    #[case::testnet("testnet", Some(GenesisHash::TESTNET))]
    #[case::other_chain("localnet", None)]
    fn genesis_hash_of__should_return_the_genesis_hash_of_mainnet_and_testnet_only(
        #[case] chain_id: &str,
        #[case] expected: Option<GenesisHash>,
    ) {
        // When
        let genesis_hash = genesis_hash_of(chain_id);

        // Then
        assert_eq!(genesis_hash, expected);
    }
}
