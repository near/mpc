use super::{
    ProtocolContractState, initializing::InitializingContractState,
    resharing::ResharingContractState, running::RunningContractState,
};
use crate::dto_mapping::IntoInterfaceType;
use near_mpc_contract_interface::types as dtos;

impl IntoInterfaceType<dtos::InitializingContractState> for &InitializingContractState {
    fn into_dto_type(self) -> dtos::InitializingContractState {
        dtos::InitializingContractState {
            domains: (&self.domains).into_dto_type(),
            epoch_id: self.epoch_id,
            generated_keys: self
                .generated_keys
                .iter()
                .map(|k| k.into_dto_type())
                .collect(),
            generating_key: (&self.generating_key).into_dto_type(),
            cancel_votes: self
                .cancel_votes
                .iter()
                .map(|p| p.into_dto_type())
                .collect(),
        }
    }
}

impl IntoInterfaceType<dtos::RunningContractState> for &RunningContractState {
    fn into_dto_type(self) -> dtos::RunningContractState {
        dtos::RunningContractState {
            domains: (&self.domains).into_dto_type(),
            keyset: (&self.keyset).into_dto_type(),
            parameters: (&self.parameters).into_dto_type(),
            add_domains_votes: (&self.add_domains_votes).into_dto_type(),
            previously_cancelled_resharing_epoch_id: self.previously_cancelled_resharing_epoch_id,
        }
    }
}

impl IntoInterfaceType<dtos::ResharingContractState> for &ResharingContractState {
    fn into_dto_type(self) -> dtos::ResharingContractState {
        dtos::ResharingContractState {
            previous_running_state: (&self.previous_running_state).into_dto_type(),
            reshared_keys: self
                .reshared_keys
                .iter()
                .map(|k| k.into_dto_type())
                .collect(),
            resharing_key: (&self.resharing_key).into_dto_type(),
            cancellation_requests: self
                .cancellation_requests
                .iter()
                .map(|a| a.into_dto_type())
                .collect(),
            per_domain_thresholds: self.per_domain_thresholds.clone(),
        }
    }
}

impl IntoInterfaceType<dtos::ProtocolContractState> for &ProtocolContractState {
    fn into_dto_type(self) -> dtos::ProtocolContractState {
        match self {
            ProtocolContractState::NotInitialized => dtos::ProtocolContractState::NotInitialized,
            ProtocolContractState::Initializing(state) => {
                dtos::ProtocolContractState::Initializing(state.into_dto_type())
            }
            ProtocolContractState::Running(state) => {
                dtos::ProtocolContractState::Running(state.into_dto_type())
            }
            ProtocolContractState::Resharing(state) => {
                dtos::ProtocolContractState::Resharing(state.into_dto_type())
            }
        }
    }
}
