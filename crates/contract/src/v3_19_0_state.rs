//! ## Overview
//! This module stores the contract state of release `3.19.0`, one of the states to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed in that release.
//!
//! ## Guideline
//! Only copy the structures that have changed since `3.19.0` and import the rest from the
//! existing codebase.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::{
    CKDRequest, SignatureRequest, VerifyForeignTransactionRequest, YieldIndex,
};
use near_sdk::{
    AccountId,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::Config,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    pending_verify_foreign_tx_v2::PendingVerifyForeignTxRequestsV2,
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
    pub(crate) protocol_state: ProtocolContractState,
    pub(crate) pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pub(crate) pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pub(crate) pending_verify_foreign_tx_requests:
        LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    pub(crate) contract_update_votes: ContractUpdateVotes,
    pub(crate) config: Config,
    pub(crate) tee_state: TeeState,
    pub(crate) accept_requests: bool,
    pub(crate) node_migrations: NodeMigrations,
    pub(crate) foreign_chains: Lazy<ForeignChainsMetadata>,
    pub(crate) tee_verifier_account_id: AccountId,
    pub(crate) tee_verifier_votes: TeeVerifierVotes,
    pub(crate) available_attestation_grants: IterableMap<AccountId, u32>,
    pub(crate) parameters_votes: GovernanceThresholdParametersVotes,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
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
            pending_verify_foreign_tx_v2_requests: PendingVerifyForeignTxRequestsV2::default(),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::{state::test_utils::gen_running_state, storage_keys::StorageKey};
    use near_sdk::env;

    fn old_contract(protocol_state: ProtocolContractState) -> MpcContract {
        MpcContract {
            protocol_state,
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            contract_update_votes: ContractUpdateVotes::default(),
            config: Config::default(),
            tee_state: TeeState::default(),
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: "verifier.near".parse().unwrap(),
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: GovernanceThresholdParametersVotes::default(),
        }
    }

    #[test]
    fn migrate__should_read_a_3_19_0_state() {
        // Given
        let running_state = ProtocolContractState::Running(gen_running_state(1));
        env::state_write(&old_contract(running_state.clone()));

        // When
        let migrated = crate::MpcContract::migrate().unwrap();

        // Then
        assert_eq!(migrated.protocol_state, running_state);
    }

    #[cfg(feature = "foreign-tx-v2")]
    #[test]
    fn from__should_start_the_foreign_tx_v2_yield_counter_at_zero() {
        // Given
        let old = old_contract(ProtocolContractState::Running(gen_running_state(1)));

        // When
        let mut migrated: crate::MpcContract = old.into();

        // Then
        assert_eq!(
            migrated
                .pending_verify_foreign_tx_v2_requests
                .take_next_yield_id(),
            PendingVerifyForeignTxRequestsV2::default().take_next_yield_id()
        );
    }
}
