//! Contract lifecycle: initialization, state migration, the genesis hash vote, and the top-level
//! state and config views.
#![expect(
    clippy::too_many_arguments,
    reason = "the `MpcContractExt::init_running` that near-sdk generates takes `self` on top of the arguments"
)]

use crate::config::Config;
use crate::dto_mapping::{IntoInterfaceType, TryIntoContractType};
use crate::errors::{DomainError, Error, InvalidState};
use crate::foreign_chains_metadata::ForeignChainsMetadata;
use crate::node_migrations::NodeMigrations;
use crate::primitives::domain::{
    AddDomainsVotes, DomainRegistry, validate_domains_against_governance,
};
use crate::primitives::key_state::{AuthenticatedAccountId, EpochId, Keyset};
use crate::primitives::proposal_hash::ToProposalHash;
use crate::primitives::threshold_votes::GovernanceThresholdParametersVotes;
use crate::primitives::thresholds::GovernanceThresholdParameters;
use crate::state::ProtocolContractState;
use crate::state::running::RunningContractState;
use crate::storage_keys::StorageKey;
use crate::tee::genesis_hash_votes::GenesisHashVotes;
use crate::tee::tee_state::TeeState;
use crate::tee::verifier_votes::TeeVerifierVotes;
use crate::update::ContractUpdateVotes;
use crate::{MpcContract, MpcContractExt, v3_19_0_state};
use mpc_primitives::hash::GenesisHash;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::store::{IterableMap, Lazy, LookupMap};
use near_sdk::{AccountId, env, log, near, state::ContractState};
use std::time::Duration;

#[near]
impl MpcContract {
    #[handle_result]
    #[init]
    pub fn init(
        parameters: dtos::GovernanceThresholdParameters,
        tee_verifier_account_id: AccountId,
        genesis_hash: GenesisHash,
        init_config: Option<dtos::InitConfig>,
    ) -> Result<Self, Error> {
        let parameters: GovernanceThresholdParameters = parameters.try_into_contract_type()?;
        // Log participant count and hash - full parameters exceed NEAR's 16KB log limit at ~100 participants
        let params_hash = env::sha256_array(borsh::to_vec(&parameters).unwrap());
        log!(
            "init: signer={}, num_participants={}, parameters_hash={:?}, tee_verifier_account_id={}, genesis_hash={}, init_config={:?}",
            env::signer_account_id(),
            parameters.participants().count(),
            params_hash,
            tee_verifier_account_id,
            genesis_hash,
            init_config,
        );
        parameters.validate()?;

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
            tee_state: TeeState::default(),
            // Frozen until every initial participant has an accepted attestation.
            accept_requests: false,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: GovernanceThresholdParametersVotes::default(),
            genesis_hash: Some(genesis_hash),
            genesis_hash_votes: GenesisHashVotes::default(),
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
        genesis_hash: GenesisHash,
        init_config: Option<dtos::InitConfig>,
    ) -> Result<Self, Error> {
        let keyset: Keyset = keyset.try_into_contract_type()?;
        let parameters: GovernanceThresholdParameters = parameters.try_into_contract_type()?;
        // Log participant count and hash - full parameters exceed NEAR's 16KB log limit at ~100 participants
        let params_hash = env::sha256_array(borsh::to_vec(&parameters).unwrap());
        log!(
            "init_running: signer={}, domains={:?}, keyset={:?}, num_participants={}, threshold={}, parameters_hash={:?}, tee_verifier_account_id={}, genesis_hash={}, init_config={:?}",
            env::signer_account_id(),
            domains,
            keyset,
            parameters.participants().count(),
            parameters.threshold().value(),
            params_hash,
            tee_verifier_account_id,
            genesis_hash,
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
            tee_state: TeeState::default(),
            // Frozen until every initial participant has an accepted attestation.
            accept_requests: false,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id,
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
            parameters_votes: GovernanceThresholdParametersVotes::default(),
            genesis_hash: Some(genesis_hash),
            genesis_hash_votes: GenesisHashVotes::default(),
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

        match try_state_read::<v3_19_0_state::MpcContract>() {
            Ok(Some(state)) => return Ok(state.into()),
            Ok(None) => return Err(InvalidState::ContractStateIsMissing.into()),
            Err(err) => {
                log!("failed to deserialize state into 3.19.0 state: {:?}", err);
            }
        };

        match try_state_read::<Self>() {
            Ok(Some(state)) => Ok(state),
            Ok(None) => Err(InvalidState::ContractStateIsMissing.into()),
            Err(err) => env::panic_str(&format!("could not deserialize contract state: {err}")),
        }
    }

    /// Votes to set the genesis hash of a contract that has none. Once a governance threshold of
    /// participants voted for the same hash, the contract stores it and allows the compose hashes
    /// that carry it. Later votes for that hash are no-ops, and votes for another return
    /// [`InvalidState::GenesisHashAlreadySet`].
    #[handle_result]
    pub fn vote_genesis_hash(&mut self, genesis_hash: GenesisHash) -> Result<(), Error> {
        log!(
            "vote_genesis_hash: signer={}, genesis_hash={}",
            env::signer_account_id(),
            genesis_hash,
        );
        Self::assert_caller_is_signer();
        let parameters = self.protocol_state.threshold_parameters_or_panic();
        let voter = AuthenticatedAccountId::new(parameters.participants())?;
        match self.genesis_hash {
            None => {}
            Some(stored) if stored == genesis_hash => return Ok(()),
            Some(_) => return Err(InvalidState::GenesisHashAlreadySet.into()),
        }
        let num_votes = self
            .genesis_hash_votes
            .vote(voter, genesis_hash.to_proposal_hash())
            .count_participants(parameters.participants());
        if parameters.threshold().is_met_by(num_votes) {
            self.genesis_hash_votes.clear();
            self.genesis_hash = Some(genesis_hash);
            self.tee_state.add_compose_hashes(
                &genesis_hash,
                Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds),
            );
        }
        Ok(())
    }

    pub fn state(&self) -> near_mpc_contract_interface::types::ProtocolContractState {
        (&self.protocol_state).into_dto_type()
    }

    pub fn config(&self) -> dtos::Config {
        dtos::Config::from(&self.config)
    }

    pub fn genesis_hash(&self) -> Option<GenesisHash> {
        self.genesis_hash
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

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{
        init_running_with_domain, running_contract_called_by_participant_via_forwarder,
    };
    use crate::primitives::test_utils::{
        bogus_genesis_hash, bogus_tee_verifier_account_id, gen_participants,
    };
    use crate::primitives::thresholds::GovernanceThreshold;
    use crate::state::test_utils::threshold_voters;
    use crate::tee::proposal::get_docker_compose_hash;
    use crate::tee::test_utils::Environment;
    use dtos::{DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold};
    use rstest::rstest;

    const PARTICIPANTS: usize = 3;
    const THRESHOLD: usize = 2;

    fn parameters() -> GovernanceThresholdParameters {
        GovernanceThresholdParameters::new(
            gen_participants(PARTICIPANTS),
            GovernanceThreshold::new(u64::try_from(THRESHOLD).unwrap()),
        )
        .unwrap()
    }

    fn contract_with_genesis_hash(
        genesis_hash: Option<GenesisHash>,
    ) -> (MpcContract, Vec<AccountId>) {
        let parameters = parameters();
        let mut contract = MpcContract::init(
            (&parameters).into_dto_type(),
            bogus_tee_verifier_account_id(),
            bogus_genesis_hash(),
            None,
        )
        .unwrap();
        contract.genesis_hash = genesis_hash;
        (contract, threshold_voters(&parameters))
    }

    #[test]
    fn init__should_store_no_attestations_and_not_accept_requests() {
        // Given
        let parameters = parameters();

        // When
        let contract = MpcContract::init(
            (&parameters).into_dto_type(),
            bogus_tee_verifier_account_id(),
            bogus_genesis_hash(),
            None,
        )
        .unwrap();

        // Then
        assert!(contract.tee_state.nodes.is_empty());
        assert!(!contract.accept_requests);
    }

    #[test]
    fn init_running__should_store_no_attestations_and_not_accept_requests() {
        // Given
        let parameters = parameters();
        let domain = DomainConfig {
            id: DomainId::default(),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        };

        // When
        let contract = init_running_with_domain(&parameters, domain);

        // Then
        assert!(contract.tee_state.nodes.is_empty());
        assert!(!contract.accept_requests);
    }

    #[rstest]
    #[case::below_threshold(&[GenesisHash::MAINNET; THRESHOLD - 1], None)]
    #[case::split_between_hashes(&[GenesisHash::MAINNET, GenesisHash::TESTNET], None)]
    #[case::threshold_reached(&[GenesisHash::MAINNET; THRESHOLD], Some(GenesisHash::MAINNET))]
    fn vote_genesis_hash__should_set_the_hash_once_a_threshold_of_participants_voted_for_it(
        #[case] votes: &[GenesisHash],
        #[case] expected: Option<GenesisHash>,
    ) {
        // Given
        let (mut contract, voters) = contract_with_genesis_hash(None);
        let mut env = Environment::new(None, None, None);

        // When
        for (voter, &genesis_hash) in voters.iter().zip(votes) {
            env.set_signer(voter);
            contract.vote_genesis_hash(genesis_hash).unwrap();
        }

        // Then
        assert_eq!(contract.genesis_hash(), expected);
        assert_eq!(
            contract.genesis_hash_votes.all().is_empty(),
            expected.is_some()
        );
    }

    #[rstest]
    #[case::stored_hash(GenesisHash::TESTNET, Ok(()))]
    #[case::other_hash(GenesisHash::MAINNET, Err(InvalidState::GenesisHashAlreadySet.into()))]
    fn vote_genesis_hash__should_keep_a_stored_hash(
        #[case] genesis_hash: GenesisHash,
        #[case] expected: Result<(), Error>,
    ) {
        // Given
        let stored_hash = GenesisHash::TESTNET;
        let (mut contract, voters) = contract_with_genesis_hash(Some(stored_hash));
        Environment::new(None, Some(voters[0].clone()), None);

        // When
        let result = contract.vote_genesis_hash(genesis_hash);

        // Then
        assert_eq!(result, expected);
        assert_eq!(contract.genesis_hash(), Some(stored_hash));
    }

    #[test]
    fn vote_genesis_hash__should_allow_compose_hashes_that_carry_it_for_allowed_pairs() {
        // Given
        let (mut contract, voters) = contract_with_genesis_hash(None);
        let genesis_hash = GenesisHash::MAINNET;
        let launcher_hash = dtos::LauncherImageHash::from([1; 32]);
        let mpc_image_hash = dtos::NodeImageHash::from([2; 32]);
        let mut env = Environment::new(None, None, None);
        for voter in &voters {
            env.set_signer(voter);
            contract
                .vote_mpc_node_manifest_digest(mpc_image_hash)
                .unwrap();
            contract.vote_add_launcher_hash(launcher_hash).unwrap();
        }

        // When
        for voter in &voters {
            env.set_signer(voter);
            contract.vote_genesis_hash(genesis_hash).unwrap();
        }

        // Then
        let compose_hash = |hash| get_docker_compose_hash(&launcher_hash, &mpc_image_hash, hash);
        assert_eq!(
            contract.allowed_launcher_compose_hashes(),
            vec![compose_hash(None), compose_hash(Some(&genesis_hash))],
        );
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn vote_genesis_hash__should_panic_when_predecessor_differs_from_signer() {
        // Given
        let mut contract = running_contract_called_by_participant_via_forwarder();

        // When
        contract
            .vote_genesis_hash(GenesisHash::MAINNET)
            .expect("expected panic when predecessor != signer");
    }
}
