pub mod initializing;
pub mod key_event;
pub mod resharing;
pub mod running;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{Error, InvalidState};
use crate::primitives::{
    domain::DomainRegistry,
    key_state::{AuthenticatedParticipantId, EpochId},
    participants::Participants,
    threshold_votes::GovernanceThresholdParametersVotes,
    thresholds::{
        GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
    },
};
use initializing::InitializingContractState;
use key_event::KeyEvent;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{DomainConfig, DomainId};
use near_sdk::{env, near};
use resharing::ResharingContractState;
use running::RunningContractState;

#[near(serializers=[borsh])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone, PartialEq))]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolContractState {
    pub fn domain_registry(&self) -> Result<&DomainRegistry, Error> {
        let domain_registry = match self {
            ProtocolContractState::Running(state) => &state.domains,
            ProtocolContractState::Resharing(state) => &state.previous_running_state.domains,
            _ => return Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        };

        Ok(domain_registry)
    }
    pub fn public_key(&self, domain_id: DomainId) -> Result<PublicKeyExtended, Error> {
        match self {
            ProtocolContractState::Running(state) => state.keyset.public_key(domain_id),
            ProtocolContractState::Resharing(state) => {
                state.previous_keyset().public_key(domain_id)
            }
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
    }
    pub fn threshold(&self) -> Result<GovernanceThreshold, Error> {
        match self {
            ProtocolContractState::Initializing(state) => {
                Ok(state.generating_key.proposed_parameters().threshold())
            }
            ProtocolContractState::Running(state) => Ok(state.parameters.threshold()),
            ProtocolContractState::Resharing(state) => {
                Ok(state.previous_running_state.parameters.threshold())
            }
            ProtocolContractState::NotInitialized => Err(InvalidState::UnexpectedProtocolState {
                state_name: self.name(),
            }
            .into()),
        }
    }
    /// The key generation in progress.
    pub fn initializing_mut(&mut self) -> Result<&mut InitializingContractState, Error> {
        match self {
            ProtocolContractState::Initializing(state) => Ok(state),
            _ => Err(InvalidState::ProtocolStateNotInitializing.into()),
        }
    }

    /// The resharing in progress.
    pub fn resharing_mut(&mut self) -> Result<&mut ResharingContractState, Error> {
        match self {
            ProtocolContractState::Resharing(state) => Ok(state),
            _ => Err(InvalidState::ProtocolStateNotResharing.into()),
        }
    }

    /// The key event of the key generation or resharing in progress.
    pub fn key_event_mut(&mut self) -> Result<&mut KeyEvent, Error> {
        match self {
            ProtocolContractState::Initializing(state) => Ok(&mut state.generating_key),
            ProtocolContractState::Resharing(state) => Ok(&mut state.resharing_key),
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
    }

    /// Casts a vote for `proposed_parameters`, returning the new protocol state if the proposal is
    /// accepted. Returns an error if the protocol is not in the Running or Resharing state.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposed_parameters: &ProposedGovernanceThresholdParameters,
        votes: &mut GovernanceThresholdParametersVotes,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Running(state) => {
                state.vote_new_parameters(prospective_epoch_id, proposed_parameters, votes)
            }
            ProtocolContractState::Resharing(state) => {
                state.vote_new_parameters(prospective_epoch_id, proposed_parameters, votes)
            }
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
        .map(|x| x.map(ProtocolContractState::Resharing))
    }

    pub fn vote_add_domains(
        &mut self,
        domains: Vec<DomainConfig>,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Running(state) => state.vote_add_domains(domains),
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
        .map(|x| x.map(ProtocolContractState::Initializing))
    }

    pub(super) fn threshold_parameters(
        &self,
    ) -> Result<&GovernanceThresholdParameters, ContractNotInitialized> {
        match self {
            ProtocolContractState::NotInitialized => Err(ContractNotInitialized),
            ProtocolContractState::Initializing(initializing_contract_state) => {
                Ok(initializing_contract_state
                    .generating_key
                    .proposed_parameters())
            }
            ProtocolContractState::Running(running_contract_state) => {
                Ok(&running_contract_state.parameters)
            }
            ProtocolContractState::Resharing(resharing_contract_state) => {
                Ok(&resharing_contract_state.previous_running_state.parameters)
            }
        }
    }

    /// Active threshold parameters, panicking on [`ContractNotInitialized`].
    pub(super) fn threshold_parameters_or_panic(&self) -> &GovernanceThresholdParameters {
        self.threshold_parameters()
            .unwrap_or_else(|ContractNotInitialized| env::panic_str("contract is not initialized"))
    }
}

impl ProtocolContractState {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractState::NotInitialized => "NotInitialized",
            ProtocolContractState::Initializing(_) => "Initializing",
            ProtocolContractState::Running(_) => "Running",
            ProtocolContractState::Resharing(_) => "Resharing",
        }
    }

    pub fn is_running_or_resharing(&self) -> bool {
        matches!(
            self,
            ProtocolContractState::Running(_) | ProtocolContractState::Resharing(_)
        )
    }

    pub fn authenticate_update_vote(&self) -> Result<(), Error> {
        match &self {
            ProtocolContractState::Initializing(state) => {
                AuthenticatedParticipantId::new(
                    state.generating_key.proposed_parameters().participants(),
                )?;
            }
            ProtocolContractState::Running(state) => {
                AuthenticatedParticipantId::new(state.parameters.participants())?;
            }
            ProtocolContractState::Resharing(state) => {
                AuthenticatedParticipantId::new(
                    state.previous_running_state.parameters.participants(),
                )?;
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState {
                    state_name: self.name(),
                }
                .into());
            }
        };
        Ok(())
    }

    /// Returns a reference to the relevant [`Participants`] list
    /// based on the current protocol phase.
    ///
    /// - [`Initializing`](ProtocolContractState::Initializing) → uses proposed participants from generating_key
    /// - [`Running`](ProtocolContractState::Running) → uses current active participants
    /// - [`Resharing`](ProtocolContractState::Resharing) → uses new participants from resharing proposal
    ///
    /// Panics if called when [`NotInitialized`](ProtocolContractState::NotInitialized).
    pub fn active_participants(&self) -> &Participants {
        match self {
            ProtocolContractState::Initializing(state) => {
                state.generating_key.proposed_parameters().participants()
            }
            ProtocolContractState::Running(state) => state.parameters.participants(),
            ProtocolContractState::Resharing(state) => {
                state.resharing_key.proposed_parameters().participants()
            }
            ProtocolContractState::NotInitialized => {
                panic!(
                    "Protocol must be Initializing, Running, or Resharing to access active participants"
                );
            }
        }
    }

    pub fn is_existing_or_prospective_participant(
        &self,
        account_id: &AccountId,
    ) -> Result<bool, Error> {
        let is_existing_or_prospective_participant = match &self {
            ProtocolContractState::Initializing(state) => state.is_participant(account_id),
            ProtocolContractState::Running(state) => state.is_participant(account_id),
            ProtocolContractState::Resharing(state) => {
                state.is_participant_or_prospective_participant(account_id)
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState {
                    state_name: self.name(),
                }
                .into());
            }
        };
        Ok(is_existing_or_prospective_participant)
    }
}

#[cfg(feature = "bench-contract-methods")]
impl ProtocolContractState {
    /// Returns mutable reference to active participants for benchmarking.
    pub fn active_participants_mut(&mut self) -> &mut Participants {
        match self {
            ProtocolContractState::Running(state) => state.parameters.participants_mut(),
            _ => panic!(
                "bench-contract-methods: active_participants_mut only works in Running state"
            ),
        }
    }
}

#[cfg(feature = "dev-utils")]
impl ProtocolContractState {
    pub fn get_domain_config(&self, domain_id: DomainId) -> Option<DomainConfig> {
        match self {
            ProtocolContractState::Running(state) => state
                .domains
                .domains()
                .iter()
                .find(|domain| domain.id == domain_id)
                .cloned(),
            ProtocolContractState::Resharing(state) => state
                .previous_running_state
                .domains
                .domains()
                .iter()
                .find(|domain| domain.id == domain_id)
                .cloned(),
            ProtocolContractState::Initializing(state) => state
                .domains
                .domains()
                .iter()
                .find(|domain| domain.id == domain_id)
                .cloned(),
            _ => None,
        }
    }

    pub fn next_domain_id(&self) -> DomainId {
        match self {
            ProtocolContractState::Running(state) => state.domains.next_domain_id(),
            ProtocolContractState::Initializing(state) => state.domains.next_domain_id(),
            ProtocolContractState::Resharing(state) => {
                state.previous_running_state.domains.next_domain_id()
            }
            _ => panic!("protocol state must be initialized"),
        }
    }

    pub fn current_epoch(&self) -> EpochId {
        match self {
            ProtocolContractState::Running(state) => state.keyset.epoch_id,
            ProtocolContractState::Initializing(state) => state.epoch_id,
            ProtocolContractState::Resharing(state) => state.previous_running_state.keyset.epoch_id,
            _ => panic!("protocol state must be initialized"),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ContractNotInitialized;

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::test_utils::{gen_initializing_state, gen_resharing_state, gen_running_state};
    use super::*;
    use rstest::rstest;

    fn not_initialized() -> ProtocolContractState {
        ProtocolContractState::NotInitialized
    }

    fn initializing() -> ProtocolContractState {
        ProtocolContractState::Initializing(gen_initializing_state(1, 0).1)
    }

    fn running() -> ProtocolContractState {
        ProtocolContractState::Running(gen_running_state(1))
    }

    fn resharing() -> ProtocolContractState {
        ProtocolContractState::Resharing(gen_resharing_state(1).1)
    }

    #[test]
    fn initializing_mut__should_return_the_state_when_initializing() {
        // Given
        let mut state = initializing();

        // When
        let result = state.initializing_mut();

        // Then
        result.unwrap();
    }

    #[rstest]
    #[case::not_initialized(not_initialized())]
    #[case::running(running())]
    #[case::resharing(resharing())]
    fn initializing_mut__should_fail_when_not_initializing(
        #[case] mut state: ProtocolContractState,
    ) {
        // When
        let err = state.initializing_mut().unwrap_err();

        // Then
        assert_eq!(err, InvalidState::ProtocolStateNotInitializing.into());
    }

    #[test]
    fn resharing_mut__should_return_the_state_when_resharing() {
        // Given
        let mut state = resharing();

        // When
        let result = state.resharing_mut();

        // Then
        result.unwrap();
    }

    #[rstest]
    #[case::not_initialized(not_initialized())]
    #[case::initializing(initializing())]
    #[case::running(running())]
    fn resharing_mut__should_fail_when_not_resharing(#[case] mut state: ProtocolContractState) {
        // When
        let err = state.resharing_mut().unwrap_err();

        // Then
        assert_eq!(err, InvalidState::ProtocolStateNotResharing.into());
    }

    #[rstest]
    #[case::initializing(initializing())]
    #[case::resharing(resharing())]
    fn key_event_mut__should_return_the_key_event_when_a_key_event_is_in_progress(
        #[case] mut state: ProtocolContractState,
    ) {
        // When
        let result = state.key_event_mut();

        // Then
        result.unwrap();
    }

    #[rstest]
    #[case::not_initialized(not_initialized())]
    #[case::running(running())]
    fn key_event_mut__should_fail_when_no_key_event_is_in_progress(
        #[case] mut state: ProtocolContractState,
    ) {
        // When
        let err = state.key_event_mut().unwrap_err();

        // Then
        assert_eq!(
            err,
            InvalidState::ProtocolStateNotRunningNorResharing.into()
        );
    }
}
