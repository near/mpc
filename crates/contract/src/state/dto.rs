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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::dto_mapping::IntoInterfaceType;
    use crate::primitives::key_state::{AttemptId, KeyEventId};
    use crate::state::key_event::tests::find_leader;
    use crate::state::test_utils::gen_initializing_state;
    use near_mpc_contract_interface::types::{self as dtos, BlockCount};
    use rstest::rstest;

    const TIMEOUT_BLOCKS: u64 = 5;

    #[rstest]
    #[case::in_its_last_block(TIMEOUT_BLOCKS, Some(AttemptId::new()))]
    #[case::once_it_timed_out(TIMEOUT_BLOCKS + 1, None)]
    fn initializing_state_dto__should_show_the_key_event_instance_only_until_it_times_out(
        #[case] blocks_since_start: u64,
        #[case] expected_attempt: Option<AttemptId>,
    ) {
        // Given
        let (mut env, mut state) = gen_initializing_state(1, 0);
        let (leader, _) = find_leader(&state.generating_key);
        env.set_signer(&leader);
        let key_event_id = KeyEventId::new(
            state.epoch_id,
            state.generating_key.domain_id(),
            AttemptId::new(),
        );
        state
            .start(key_event_id, BlockCount::from(TIMEOUT_BLOCKS))
            .unwrap();
        env.advance_block_height(blocks_since_start);

        // When
        let dto: dtos::InitializingContractState = (&state).into_dto_type();

        // Then
        let shown_attempt = dto
            .generating_key
            .instance
            .map(|instance| instance.attempt_id);
        assert_eq!(shown_attempt, expected_attempt);
    }
}
