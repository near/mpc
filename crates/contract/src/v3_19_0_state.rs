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
            genesis_hash: known_genesis_hash(),
        }
    }
}

/// The `3.19.0` contract does not store the genesis hash of its chain, which is known only for the
/// production contracts. Any other contract gets a hash no chain has, so TEE nodes refuse to serve
/// it until it is redeployed.
fn known_genesis_hash() -> GenesisHash {
    let genesis_hash = match env::current_account_id().as_str() {
        "v1.signer" => "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H",
        "v1.signer-prod.testnet" => "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b",
        _ => return GenesisHash::from([0; 32]),
    };
    genesis_hash
        .parse()
        .expect("the production genesis hashes are valid")
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use rstest::rstest;

    #[rstest]
    #[case::mainnet("v1.signer", "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H")]
    #[case::testnet(
        "v1.signer-prod.testnet",
        "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b"
    )]
    #[case::other_contract("mpc.sandbox", "11111111111111111111111111111111")]
    fn known_genesis_hash__should_return_the_genesis_hash_of_the_production_contract_s_chain(
        #[case] contract_id: &str,
        #[case] genesis_hash: &str,
    ) {
        // Given
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(contract_id.parse().unwrap())
                .build()
        );

        // When
        let known = known_genesis_hash();

        // Then
        assert_eq!(known, genesis_hash.parse().unwrap());
    }
}
