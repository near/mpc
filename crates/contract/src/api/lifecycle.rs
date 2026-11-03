//! Contract lifecycle: initialization, state migration, and the top-level
//! state and config views.

use crate::config::Config;
use crate::dto_mapping::{IntoInterfaceType, TryIntoContractType};
use crate::errors::{DomainError, Error, InvalidState};
use crate::foreign_chains_metadata::ForeignChainsMetadata;
use crate::node_migrations::NodeMigrations;
use crate::primitives::domain::{
    AddDomainsVotes, DomainRegistry, validate_domains_against_governance,
};
use crate::primitives::key_state::{EpochId, Keyset};
use crate::primitives::threshold_votes::GovernanceThresholdParametersVotes;
use crate::primitives::thresholds::GovernanceThresholdParameters;
use crate::state::ProtocolContractState;
use crate::state::running::RunningContractState;
use crate::storage_keys::StorageKey;
use crate::tee::tee_state::TeeState;
use crate::tee::verifier_votes::TeeVerifierVotes;
use crate::update::ContractUpdateVotes;
use crate::{MpcContract, MpcContractExt, v3_18_0_state};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::store::{IterableMap, Lazy, LookupMap};
use near_sdk::{AccountId, env, log, near, state::ContractState};
use std::iter;

#[near]
impl MpcContract {
    #[handle_result]
    #[init]
    pub fn init(
        parameters: dtos::GovernanceThresholdParameters,
        tee_verifier_account_id: AccountId,
        init_config: Option<dtos::InitConfig>,
    ) -> Result<Self, Error> {
        let parameters: GovernanceThresholdParameters = parameters.try_into_contract_type()?;
        // Log participant count and hash - full parameters exceed NEAR's 16KB log limit at ~100 participants
        let params_hash = env::sha256_array(borsh::to_vec(&parameters).unwrap());
        log!(
            "init: signer={}, num_participants={}, parameters_hash={:?}, tee_verifier_account_id={}, init_config={:?}",
            env::signer_account_id(),
            parameters.participants().count(),
            params_hash,
            tee_verifier_account_id,
            init_config,
        );
        parameters.validate()?;

        // TODO(#1087): Every participant must have a valid attestation, otherwise we risk
        // participants being immediately kicked out once contract transitions into running.
        let initial_participants = parameters.participants();
        let tee_state = TeeState::with_mocked_participant_attestations(initial_participants);

        let config: Config = init_config.map(Into::into).unwrap_or_default();

        Ok(Self {
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                DomainRegistry::default(),
                Keyset::new(EpochId::new(0), Vec::new()),
                parameters,
                AddDomainsVotes::default(),
            )),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            contract_update_votes: ContractUpdateVotes::default(),
            config,
            tee_state,
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: GovernanceThresholdParametersVotes::default(),
        })
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init]
    #[handle_result]
    pub fn init_running(
        domains: Vec<dtos::DomainConfig>,
        next_domain_id: dtos::DomainId,
        keyset: dtos::Keyset,
        parameters: dtos::GovernanceThresholdParameters,
        tee_verifier_account_id: AccountId,
        init_config: Option<dtos::InitConfig>,
    ) -> Result<Self, Error> {
        let keyset: Keyset = keyset.try_into_contract_type()?;
        let parameters: GovernanceThresholdParameters = parameters.try_into_contract_type()?;
        // Log participant count and hash - full parameters exceed NEAR's 16KB log limit at ~100 participants
        let params_hash = env::sha256_array(borsh::to_vec(&parameters).unwrap());
        log!(
            "init_running: signer={}, domains={:?}, keyset={:?}, num_participants={}, threshold={}, parameters_hash={:?}, tee_verifier_account_id={}, init_config={:?}",
            env::signer_account_id(),
            domains,
            keyset,
            parameters.participants().count(),
            parameters.threshold().value(),
            params_hash,
            tee_verifier_account_id,
            init_config,
        );
        parameters.validate()?;
        let domains = DomainRegistry::from_raw_validated(domains, next_domain_id)?;
        // Keep the GovernanceThreshold at least as large as the largest ReconstructionThreshold.
        validate_domains_against_governance(
            domains.domains(),
            parameters.participants().count(),
            parameters.threshold(),
        )?;

        // Check that the domains match exactly those in the keyset.
        let domain_ids_from_domains = domains.domains().iter().map(|d| d.id).collect::<Vec<_>>();
        let domain_ids_from_keyset = keyset
            .domains
            .iter()
            .map(|k| k.domain_id)
            .collect::<Vec<_>>();
        if domain_ids_from_domains != domain_ids_from_keyset {
            return Err(DomainError::DomainsMismatch.into());
        }

        let initial_participants = parameters.participants();
        let tee_state = TeeState::with_mocked_participant_attestations(initial_participants);

        let config: Config = init_config.map(Into::into).unwrap_or_default();

        Ok(MpcContract {
            config,
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                domains,
                keyset,
                parameters,
                AddDomainsVotes::default(),
            )),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            contract_update_votes: Default::default(),
            tee_state,
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: GovernanceThresholdParametersVotes::default(),
        })
    }

    /// This will be called internally by the contract to migrate the state when a new contract
    /// is deployed. This function should be changed every time state is changed to do the proper
    /// migrate flow.
    ///
    /// If nothing is changed, then this function will just return the current state. If it fails
    /// to read the state, then it will return an error. It also fails if a participant of the
    /// 3.18.0 state uses a TLS key that does not hold a node the participant owns, which reverts
    /// the whole upgrade.
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, Error> {
        log!("migrating contract");

        match try_state_read::<v3_18_0_state::MpcContract>() {
            Ok(Some(state)) => {
                let contract: Self = state.into();
                // TODO(#5045): remove once no network runs 3.18.0
                contract.assert_participants_own_their_tls_keys()?;
                return Ok(contract);
            }
            Ok(None) => return Err(InvalidState::ContractStateIsMissing.into()),
            Err(err) => {
                log!("failed to deserialize state into 3.18.0 state: {:?}", err);
            }
        };

        match try_state_read::<Self>() {
            Ok(Some(state)) => Ok(state),
            Ok(None) => Err(InvalidState::ContractStateIsMissing.into()),
            Err(err) => env::panic_str(&format!("could not deserialize contract state: {err}")),
        }
    }

    fn assert_participants_own_their_tls_keys(&self) -> Result<(), Error> {
        let participants = self
            .protocol_state
            .threshold_parameters_or_panic()
            .participants();
        for (account_id, _, participant_info) in participants.participants() {
            let migration_destination = self
                .node_migrations
                .ongoing_migration(account_id)
                .map(|migration| &migration.destination_node_info.tls_public_key);
            for tls_public_key in
                iter::once(&participant_info.tls_public_key).chain(migration_destination)
            {
                if self.tee_state.node_of(account_id, tls_public_key).is_none() {
                    return Err(InvalidState::ParticipantNodeMissing {
                        account_id: account_id.clone(),
                        tls_public_key: tls_public_key.clone(),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    pub fn state(&self) -> near_mpc_contract_interface::types::ProtocolContractState {
        (&self.protocol_state).into_dto_type()
    }

    pub fn config(&self) -> dtos::Config {
        dtos::Config::from(&self.config)
    }

    // contract version
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}

fn try_state_read<T: borsh::BorshDeserialize>() -> Result<Option<T>, std::io::Error> {
    env::storage_read(MpcContract::state_key())
        .map(|data| T::try_from_slice(&data))
        .transpose()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::{
        api::test_utils::{destination_of, initializing_state, resharing_state, running_state},
        primitives::test_utils::node_id_for,
    };
    use rstest::rstest;
    use std::assert_matches;

    fn contract_with_participant_nodes(protocol_state: ProtocolContractState) -> MpcContract {
        let mut contract = MpcContract::new_from_protocol_state(protocol_state);
        contract.tee_state = TeeState::with_mocked_participant_attestations(
            contract
                .protocol_state
                .threshold_parameters_or_panic()
                .participants(),
        );
        contract
    }

    #[rstest]
    fn assert_participants_own_their_tls_keys__should_accept_participants_owning_their_nodes(
        #[values(running_state(), initializing_state(), resharing_state())]
        protocol_state: ProtocolContractState,
    ) {
        // Given
        let contract = contract_with_participant_nodes(protocol_state);

        // When
        let result = contract.assert_participants_own_their_tls_keys();

        // Then
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn assert_participants_own_their_tls_keys__should_reject_a_participant_without_its_node() {
        // Given
        let mut contract = contract_with_participant_nodes(running_state());
        let (account_id, _, participant_info) =
            contract.protocol_state.active_participants().participants()[0].clone();
        contract
            .tee_state
            .nodes
            .remove(&participant_info.tls_public_key);

        // When
        let result = contract.assert_participants_own_their_tls_keys();

        // Then
        assert_eq!(
            result,
            Err(InvalidState::ParticipantNodeMissing {
                account_id,
                tls_public_key: participant_info.tls_public_key,
            }
            .into())
        );
    }

    #[test]
    fn assert_participants_own_their_tls_keys__should_reject_a_migration_destination_without_the_participants_node()
     {
        // Given
        let mut contract = contract_with_participant_nodes(running_state());
        let (account_id, _, _) =
            contract.protocol_state.active_participants().participants()[0].clone();
        let destination = destination_of(&node_id_for(&account_id));
        contract
            .node_migrations
            .set_destination_node_info(account_id.clone(), destination.clone());

        // When
        let result = contract.assert_participants_own_their_tls_keys();

        // Then
        assert_eq!(
            result,
            Err(InvalidState::ParticipantNodeMissing {
                account_id,
                tls_public_key: destination.destination_node_info.tls_public_key,
            }
            .into())
        );
    }
}
