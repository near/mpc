pub mod initializing;
pub mod key_event;
pub mod resharing;
pub mod running;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidState};
use crate::primitives::{
    domain::{DomainConfig, DomainId, DomainRegistry, SignatureScheme},
    key_state::{AuthenticatedParticipantId, EpochId, KeyEventId},
    participants::Participants,
    thresholds::{Threshold, ThresholdParameters},
};
use initializing::InitializingContractState;
use near_sdk::{near, AccountId};
use resharing::ResharingContractState;
use running::RunningContractState;

#[near(serializers=[borsh, json])]
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
    pub fn threshold(&self) -> Result<Threshold, Error> {
        match self {
            ProtocolContractState::Initializing(state) => {
                Ok(state.generating_key.proposed_parameters().threshold())
            }
            ProtocolContractState::Running(state) => Ok(state.parameters.threshold()),
            ProtocolContractState::Resharing(state) => {
                Ok(state.previous_running_state.parameters.threshold())
            }
            ProtocolContractState::NotInitialized => {
                Err(InvalidState::UnexpectedProtocolState.into())
            }
        }
    }
    pub fn start_keygen_instance(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotInitializing.into());
        };
        state.start(key_event_id, key_event_timeout_blocks)
    }
    pub fn start_reshare_instance(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state.start(key_event_id, key_event_timeout_blocks)
    }
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state
            .vote_reshared(key_event_id)
            .map(|x| x.map(ProtocolContractState::Running))
    }

    pub fn vote_cancel_resharing(&mut self) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state
            .vote_cancel_resharing()
            .map(|x| x.map(ProtocolContractState::Running))
    }

    /// Casts a vote for `public_key` in `key_event_id` during Initialization.
    /// Fails if the protocol is not in `Initializing` state.
    /// Returns the new protocol state if enough votes have been submitted.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKeyExtended,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotInitializing.into());
        };
        state
            .vote_pk(key_event_id, public_key)
            .map(|x| x.map(ProtocolContractState::Running))
    }

    /// Casts a vote for `proposed_parameters`, returning the new protocol state if the proposal is
    /// accepted. Returns an error if the protocol is not in the Running or Resharing state.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposed_parameters: &ThresholdParameters,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Running(state) => {
                state.vote_new_parameters(prospective_epoch_id, proposed_parameters)
            }
            ProtocolContractState::Resharing(state) => {
                state.vote_new_parameters(prospective_epoch_id, proposed_parameters)
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

    pub fn vote_abort_key_event_instance(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        match self {
            ProtocolContractState::Resharing(state) => state.vote_abort(key_event_id),
            ProtocolContractState::Initializing(state) => state.vote_abort(key_event_id),
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
    }

    pub fn vote_cancel_keygen(
        &mut self,
        next_domain_id: u64,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Initializing(state) => state.vote_cancel(next_domain_id),
            _ => Err(InvalidState::ProtocolStateNotInitializing.into()),
        }
        .map(|x| x.map(ProtocolContractState::Running))
    }

    pub fn most_recent_domain_for_protocol(
        &self,
        signature_scheme: SignatureScheme,
    ) -> Result<DomainId, Error> {
        self.domain_registry()?
            .most_recent_domain_for_protocol(signature_scheme)
            .ok_or_else(|| DomainError::NoSuchDomain.into())
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
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        };
        Ok(())
    }
    /// Returns a reference to the relevant `Participants` list
    /// based on the current protocol phase.
    ///
    /// - `Initializing` → uses proposed participants from generating_key
    /// - `Running` → uses current active participants
    /// - `Resharing` → uses new participants from resharing proposal
    ///
    /// Panics if called when `NotInitialized`.
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
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        };
        Ok(is_existing_or_prospective_participant)
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
}
