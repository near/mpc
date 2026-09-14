// applied on module since near proc macro is unable to apply the expect lint
#![expect(deprecated, reason = "ForeignChainConfiguration is being deprecated")]
#![doc = include_str!("../README.md")]

pub mod api;
pub mod config;
pub mod crypto_shared;
pub mod errors;
pub mod foreign_chain_rpc;
pub mod foreign_chains_metadata;
pub mod node_migrations;
pub mod primitives;
pub mod state;
pub mod storage_keys;
pub mod tee;
pub mod update;
#[cfg(feature = "dev-utils")]
pub mod utils;

pub mod v3_14_0_state;

#[cfg(feature = "bench-contract-methods")]
mod bench;
mod dto_mapping;
mod pending_requests;
#[cfg(feature = "sandbox-test-methods")]
mod sandbox_test_methods;

/// Re-export of the fan-out cap so sandbox tests can lock against the same source of
/// truth as the contract rather than duplicating the literal.
#[cfg(feature = "sandbox-test-methods")]
pub use crate::pending_requests::MAX_PENDING_REQUEST_FAN_OUT;

use crate::{
    foreign_chains_metadata::{ForeignChainsMetadata, SupportedForeignChainsByNode},
    tee::tee_state::TeeState,
    tee::verifier_votes::TeeVerifierVotes,
    update::ProposedUpdates,
};
use config::Config;
use near_mpc_contract_interface::types::{
    CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};

use near_sdk::{
    AccountId, env, near,
    store::{IterableMap, Lazy, LookupMap},
};
use node_migrations::NodeMigrations;

use state::ProtocolContractState;

#[near(contract_state)]
#[derive(Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    // TODO(#3475): drop this once we upgrade the contract and nodes start using
    // the new API.
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    /// The verifier contract account trusted for DCAP verification. An
    /// [`Attestation::Dstack`](mpc_attestation::attestation::Attestation::Dstack) submission
    /// offloads quote verification to this account.
    tee_verifier_account_id: AccountId,
    tee_verifier_votes: TeeVerifierVotes,
    /// A row is removed at zero, so the map holds no entry for an account with none.
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl Default for MpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}

#[cfg(all(test, feature = "__abi-generate", not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn mpc_contract_borsh_schema_has_not_changed() {
        let schema = borsh::schema::BorshSchemaContainer::for_type::<MpcContract>();
        insta::assert_debug_snapshot!(schema);
    }
}
