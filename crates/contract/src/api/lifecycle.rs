//! Contract lifecycle: initialization, state migration, and the top-level
//! state and config views.

use crate::config::Config;
use crate::dto_mapping::{IntoInterfaceType, TryIntoContractType};
use crate::errors::{DomainError, Error, InvalidState};
use crate::foreign_chains_metadata::ForeignChainsMetadata;
use crate::node_migrations::NodeMigrations;
use crate::primitives::domain::{AddDomainsVotes, DomainRegistry, max_reconstruction_threshold};
use crate::primitives::key_state::{EpochId, Keyset};
use crate::primitives::thresholds::GovernanceThresholdParameters;
use crate::state::ProtocolContractState;
use crate::state::running::RunningContractState;
use crate::storage_keys::StorageKey;
use crate::tee::tee_state::TeeState;
use crate::tee::verifier_votes::TeeVerifierVotes;
use crate::update::ProposedUpdates;
use crate::{MpcContract, MpcContractExt, v3_14_0_state};
use dtos::DomainConfig;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::store::{IterableMap, Lazy, LookupMap};
use near_sdk::{env, log, near};

#[near]
impl MpcContract {
    #[handle_result]
    #[init]
    pub fn init(
        parameters: dtos::GovernanceThresholdParameters,
        init_config: Option<dtos::InitConfig>,
    ) -> Result<Self, Error> {
        let parameters: GovernanceThresholdParameters = parameters.try_into_contract_type()?;
        // Log participant count and hash - full parameters exceed NEAR's 16KB log limit at ~100 participants
        let params_hash = env::sha256_array(borsh::to_vec(&parameters).unwrap());
        log!(
            "init: signer={}, num_participants={}, parameters_hash={:?}, init_config={:?}",
            env::signer_account_id(),
            parameters.participants().len(),
            params_hash,
            init_config,
        );
        parameters.validate()?;

        // TODO(#1087): Every participant must have a valid attestation, otherwise we risk
        // participants being immediately kicked out once contract transitions into running.
        let initial_participants = parameters.participants();
        let tee_state = TeeState::with_mocked_participant_attestations(initial_participants);

        let config: Config = match init_config {
            Some(c) => c.try_into()?,
            None => Config::default(),
        };

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
            proposed_updates: ProposedUpdates::default(),
            config,
            tee_state,
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            node_foreign_chain_support: Default::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: None,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        })
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init]
    #[handle_result]
    pub fn init_running(
        domains: Vec<DomainConfig>,
        next_domain_id: u64,
        keyset: dtos::Keyset,
        parameters: dtos::GovernanceThresholdParameters,
        init_config: Option<dtos::InitConfig>,
    ) -> Result<Self, Error> {
        let keyset: Keyset = keyset.try_into_contract_type()?;
        let parameters: GovernanceThresholdParameters = parameters.try_into_contract_type()?;
        // Log participant count and hash - full parameters exceed NEAR's 16KB log limit at ~100 participants
        let params_hash = env::sha256_array(borsh::to_vec(&parameters).unwrap());
        log!(
            "init_running: signer={}, domains={:?}, keyset={:?}, num_participants={}, threshold={}, parameters_hash={:?}, init_config={:?}",
            env::signer_account_id(),
            domains,
            keyset,
            parameters.participants().len(),
            parameters.threshold().value(),
            params_hash,
            init_config,
        );
        parameters.validate()?;
        let domains = DomainRegistry::from_raw_validated(domains, next_domain_id)?;
        let num_participants = parameters.participants().len() as u64;
        for domain in domains.domains() {
            crate::primitives::domain::validate_domain_reconstruction_threshold(
                domain,
                num_participants,
            )?;
        }
        // Keep the GovernanceThreshold at least as large as the largest ReconstructionThreshold.
        GovernanceThresholdParameters::validate_governance_against_reconstruction(
            num_participants,
            parameters.threshold(),
            max_reconstruction_threshold(domains.domains()),
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

        let config: Config = match init_config {
            Some(c) => c.try_into()?,
            None => Config::default(),
        };

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
            proposed_updates: Default::default(),
            tee_state,
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            node_foreign_chain_support: Default::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: None,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        })
    }

    /// This will be called internally by the contract to migrate the state when a new contract
    /// is deployed. This function should be changed every time state is changed to do the proper
    /// migrate flow.
    ///
    /// If nothing is changed, then this function will just return the current state. If it fails
    /// to read the state, then it will return an error.
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, Error> {
        log!("migrating contract");

        match try_state_read::<v3_14_0_state::MpcContract>() {
            Ok(Some(state)) => return Ok(state.into()),
            Ok(None) => return Err(InvalidState::ContractStateIsMissing.into()),
            Err(err) => {
                log!("failed to deserialize state into 3.14.0 state: {:?}", err);
            }
        };

        match try_state_read::<Self>() {
            Ok(Some(state)) => Ok(state),
            Ok(None) => Err(InvalidState::ContractStateIsMissing.into()),
            Err(err) => env::panic_str(&format!("could not deserialize contract state: {err}")),
        }
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
    env::storage_read(b"STATE")
        .map(|data| T::try_from_slice(&data))
        .transpose()
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::gen_participants;
    use crate::primitives::thresholds::GovernanceThreshold;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{NearToken, testing_env};

    #[test]
    fn init__should_reject_launcher_ttl_below_attestation_validity() {
        // Given a launcher TTL one second below the attestation validity window.
        let participants = gen_participants(3);
        let signer = participants.participants()[0].0.clone();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(signer.clone())
                .predecessor_account_id(signer)
                .attached_deposit(NearToken::from_near(1))
                .build()
        );
        let parameters =
            GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2)).unwrap();
        let bad_config = dtos::InitConfig {
            launcher_hash_unused_ttl_seconds: Some(
                mpc_attestation::attestation::DEFAULT_EXPIRATION_DURATION_SECONDS - 1,
            ),
            ..Default::default()
        };

        // When init is called with that config.
        let err = MpcContract::init((&parameters).into_dto_type(), Some(bad_config))
            .expect_err("init must reject a launcher TTL below the attestation validity window");

        // Then it fails, pointing at the invalid config field.
        assert!(
            format!("{err:?}").contains("launcher_hash_unused_ttl_seconds"),
            "error should point at the invalid config field, got: {err:?}"
        );
    }
}
